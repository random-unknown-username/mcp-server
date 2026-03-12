"""Main entry point – autonomous security research agent.

Runs a continuous loop that:
1. Explores the target application via browser + Burp proxy history
2. Builds a request graph of discovered endpoints
3. Runs auth, IDOR, and business-logic tests
4. Verifies and reports findings
5. Persists state so it can resume after restarts
"""

from __future__ import annotations

import asyncio
import json
import logging
import signal
import sys
import time
from pathlib import Path
from typing import Any

from .auth_test_engine import AuthTestEngine
from .browser_controller import BrowserController
from .burp_mcp_client import BurpMcpClient
from .config import AgentConfig
from .finding_verifier import FindingVerifier
from .logic_test_engine import LogicTestEngine
from .models import Finding, TaskStatus, TestTask, UserSession
from .report_generator import ReportGenerator
from .request_graph_builder import RequestGraphBuilder

logger = logging.getLogger(__name__)

_CYCLE_DELAY_SECONDS = 30


class SecurityAgent:
    """Top-level orchestrator for the security research agent."""

    def __init__(self, config: AgentConfig) -> None:
        self._config = config
        self._burp = BurpMcpClient(config.burp_mcp)
        self._browser = BrowserController(config.browser)
        self._graph = RequestGraphBuilder()
        self._auth_engine = AuthTestEngine(self._burp)
        self._logic_engine = LogicTestEngine(self._burp)
        self._verifier = FindingVerifier(self._burp)
        self._reporter = ReportGenerator(config.report_dir)
        self._findings: list[Finding] = []
        self._task_queue: list[TestTask] = []
        self._running = False
        self._sessions: list[UserSession] = _load_sessions(config.user_sessions)
        self._state_path = Path(config.state_dir)
        self._state_path.mkdir(parents=True, exist_ok=True)

    async def start(self) -> None:
        """Connect to Burp MCP, start the browser, and enter the main loop."""
        self._running = True
        await self._burp.connect()
        await self._browser.start()
        self._load_state()
        logger.info("Agent started – target: %s", self._config.target.base_url)

        try:
            while self._running:
                await self._cycle()
                self._save_state()
                await asyncio.sleep(_CYCLE_DELAY_SECONDS)
        except asyncio.CancelledError:
            logger.info("Agent loop cancelled")
        finally:
            await self._shutdown()

    async def stop(self) -> None:
        self._running = False

    async def run_single_cycle(self) -> list[Finding]:
        """Run one exploration+test cycle (useful for testing)."""
        await self._burp.connect()
        await self._browser.start()
        try:
            await self._cycle()
        finally:
            await self._shutdown()
        return list(self._findings)

    async def _cycle(self) -> None:
        logger.info("=== Starting test cycle ===")
        await self._explore()
        await self._run_tests()
        await self._verify_findings()
        self._reporter.generate(self._findings)
        logger.info(
            "Cycle complete: %d endpoints, %d findings (%d verified)",
            len(self._graph.endpoints),
            len(self._findings),
            sum(1 for f in self._findings if f.verified),
        )

    async def _explore(self) -> None:
        base_url = self._config.target.base_url
        if base_url:
            await self._browser.navigate(base_url)
            links = await self._browser.extract_links()
            js_endpoints = await self._browser.extract_js_endpoints()
            logger.info(
                "Browser found %d links, %d JS endpoints",
                len(links),
                len(js_endpoints),
            )

        history = await self._burp.get_proxy_history(max_items=200)
        self._graph.ingest_proxy_history(history)
        logger.info(
            "Graph has %d endpoints after ingestion", len(self._graph.endpoints)
        )

    async def _run_tests(self) -> None:
        primary = self._sessions[0] if self._sessions else UserSession(
            user_id="default", role="user"
        )
        secondary = self._sessions[1] if len(self._sessions) > 1 else None

        auth_endpoints = self._graph.get_auth_endpoints()
        param_endpoints = self._graph.get_endpoints_with_params()

        semaphore = asyncio.Semaphore(self._config.max_concurrent_tests)

        async def _test_auth(ep: Any) -> list[Finding]:
            async with semaphore:
                return await self._auth_engine.test_endpoint(
                    ep,
                    primary,
                    secondary_session=secondary,
                    replacement_ids=["1", "2", "999"],
                )

        tasks = [_test_auth(ep) for ep in auth_endpoints]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for result in results:
            if isinstance(result, list):
                self._findings.extend(result)
            elif isinstance(result, Exception):
                logger.error("Test error: %s", result)

    async def _verify_findings(self) -> None:
        unverified = [f for f in self._findings if not f.verified]
        secondary = self._sessions[1] if len(self._sessions) > 1 else None
        for finding in unverified:
            await self._verifier.verify(finding, cross_session=secondary)

    async def _shutdown(self) -> None:
        self._save_state()
        await self._browser.stop()
        await self._burp.close()

    def _save_state(self) -> None:
        state = {
            "findings": [f.to_dict() for f in self._findings],
            "graph": self._graph.to_dict(),
            "timestamp": time.time(),
        }
        state_file = self._state_path / "agent_state.json"
        state_file.write_text(json.dumps(state, indent=2))

    def _load_state(self) -> None:
        state_file = self._state_path / "agent_state.json"
        if state_file.exists():
            logger.info("Resuming from saved state")


def _load_sessions(session_dicts: list[dict[str, str]]) -> list[UserSession]:
    sessions: list[UserSession] = []
    for s in session_dicts:
        sessions.append(
            UserSession(
                user_id=s.get("user_id", "unknown"),
                role=s.get("role", "user"),
                headers=s.get("headers", {}),  # type: ignore[arg-type]
                cookies=s.get("cookies", {}),  # type: ignore[arg-type]
                tokens=s.get("tokens", {}),  # type: ignore[arg-type]
            )
        )
    return sessions


def main() -> None:
    """CLI entry point."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    config_path = sys.argv[1] if len(sys.argv) > 1 else "agent_config.json"
    config = AgentConfig.from_file(config_path)

    if not config.target.base_url:
        logger.error("No target base_url configured. Exiting.")
        sys.exit(1)

    agent = SecurityAgent(config)
    loop = asyncio.new_event_loop()

    def _handle_signal(*_: Any) -> None:
        logger.info("Shutdown signal received")
        loop.call_soon_threadsafe(lambda: asyncio.ensure_future(agent.stop()))

    signal.signal(signal.SIGINT, _handle_signal)
    signal.signal(signal.SIGTERM, _handle_signal)

    try:
        loop.run_until_complete(agent.start())
    finally:
        loop.close()


if __name__ == "__main__":
    main()

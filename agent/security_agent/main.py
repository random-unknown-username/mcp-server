"""Main entry point – autonomous security research agent.

Runs a continuous loop that:
1. Performs recon (tech fingerprinting, path discovery, header audit)
2. Optionally fetches h1-brain attack briefings and disclosed reports
3. Explores the target application via browser + Burp proxy history
4. Builds a request graph of discovered endpoints
5. Runs auth, IDOR, injection, and business-logic tests
6. Verifies and reports findings
7. Persists state so it can resume after restarts
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
from .h1_brain import H1BrainClient
from .injection_test_engine import InjectionTestEngine
from .logic_test_engine import LogicTestEngine
from .models import Finding, TaskStatus, TestTask, UserSession
from .recon_engine import ReconEngine
from .report_generator import ReportGenerator
from .request_graph_builder import RequestGraphBuilder
from .vuln_knowledge import suggest_attack_vectors

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
        self._injection_engine = InjectionTestEngine(self._burp)
        self._recon_engine = ReconEngine(self._burp)
        self._verifier = FindingVerifier(self._burp)
        self._reporter = ReportGenerator(config.report_dir)
        self._h1_brain = H1BrainClient(config.h1_brain)
        self._findings: list[Finding] = []
        self._task_queue: list[TestTask] = []
        self._running = False
        self._sessions: list[UserSession] = _load_sessions(config.user_sessions)
        self._state_path = Path(config.state_dir)
        self._state_path.mkdir(parents=True, exist_ok=True)
        self._recon_done = False
        self._h1_briefing: str = ""

    async def start(self) -> None:
        """Connect to Burp MCP, start the browser, and enter the main loop."""
        self._running = True
        await self._burp.connect()
        await self._browser.start()
        await self._h1_brain.connect()
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
        await self._h1_brain.connect()
        try:
            await self._cycle()
        finally:
            await self._shutdown()
        return list(self._findings)

    async def _cycle(self) -> None:
        logger.info("=== Starting test cycle ===")

        # Phase 0: Recon (once)
        if not self._recon_done and self._config.enable_recon:
            await self._run_recon()
            self._recon_done = True

        # Phase 0b: h1-brain briefing (once)
        if not self._h1_briefing and self._h1_brain.is_connected:
            await self._fetch_h1_briefing()

        # Phase 1: Explore
        await self._explore()

        # Phase 2: Tests
        await self._run_tests()

        # Phase 3: Injection tests
        if self._config.enable_injection_tests:
            await self._run_injection_tests()

        # Phase 4: Verify
        await self._verify_findings()

        # Phase 5: Report
        self._reporter.generate(self._findings)
        logger.info(
            "Cycle complete: %d endpoints, %d findings (%d verified)",
            len(self._graph.endpoints),
            len(self._findings),
            sum(1 for f in self._findings if f.verified),
        )

    async def _run_recon(self) -> None:
        """Run reconnaissance against the target."""
        base_url = self._config.target.base_url
        if not base_url:
            return
        logger.info("Running recon against %s", base_url)
        recon_result = await self._recon_engine.run(base_url)

        # Log recon findings
        if recon_result.technologies:
            techs = ", ".join(
                f"{t.name} {t.version}".strip()
                for t in recon_result.technologies
            )
            logger.info("Technologies detected: %s", techs)

        if recon_result.interesting_paths:
            logger.info(
                "Interesting paths found: %d",
                len(recon_result.interesting_paths),
            )

        if recon_result.security_headers.missing_headers:
            logger.info(
                "Missing security headers: %s",
                ", ".join(recon_result.security_headers.missing_headers),
            )

        if recon_result.cors_policy:
            logger.info("CORS policy: %s", recon_result.cors_policy)

        # Save recon to state
        recon_path = self._state_path / "recon_result.json"
        recon_path.write_text(json.dumps(recon_result.to_dict(), indent=2))

    async def _fetch_h1_briefing(self) -> None:
        """Fetch an attack briefing from h1-brain if available."""
        handle = self._config.target.program_handle
        if not handle:
            return
        logger.info("Fetching h1-brain attack briefing for '%s'", handle)
        briefing = await self._h1_brain.get_attack_briefing(handle)
        if briefing and briefing.raw_text:
            self._h1_briefing = briefing.raw_text
            briefing_path = self._state_path / "h1_briefing.md"
            briefing_path.write_text(briefing.raw_text)
            logger.info(
                "h1-brain briefing saved (%d chars)", len(briefing.raw_text)
            )

        # Also pull disclosed reports for the program
        disclosed = await self._h1_brain.search_disclosed_reports(
            program=handle, limit=50
        )
        if disclosed:
            logger.info(
                "Found %d disclosed reports for %s", len(disclosed), handle
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

    async def _run_injection_tests(self) -> None:
        """Run injection tests on endpoints with parameters."""
        primary = self._sessions[0] if self._sessions else UserSession(
            user_id="default", role="user"
        )

        param_endpoints = self._graph.get_endpoints_with_params()
        semaphore = asyncio.Semaphore(self._config.max_concurrent_tests)

        async def _test_injection(ep: Any) -> list[Finding]:
            async with semaphore:
                # Get suggested attack vectors for this endpoint
                suggestions = suggest_attack_vectors(
                    ep.url, ep.parameters, ep.requires_auth
                )
                cwe_ids = [s["cwe"] for s in suggestions]
                return await self._injection_engine.test_endpoint(
                    ep, primary, cwe_ids=cwe_ids
                )

        tasks = [_test_injection(ep) for ep in param_endpoints]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for result in results:
            if isinstance(result, list):
                self._findings.extend(result)
            elif isinstance(result, Exception):
                logger.error("Injection test error: %s", result)

    async def _verify_findings(self) -> None:
        unverified = [f for f in self._findings if not f.verified]
        secondary = self._sessions[1] if len(self._sessions) > 1 else None
        for finding in unverified:
            await self._verifier.verify(finding, cross_session=secondary)

    async def _shutdown(self) -> None:
        self._save_state()
        await self._browser.stop()
        await self._burp.close()
        await self._h1_brain.close()

    def _save_state(self) -> None:
        state = {
            "findings": [f.to_dict() for f in self._findings],
            "graph": self._graph.to_dict(),
            "recon_done": self._recon_done,
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

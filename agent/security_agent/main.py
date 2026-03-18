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

import argparse
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
from .config import AgentConfig, generate_default_config
from .finding_verifier import FindingVerifier
from .gcp_iam_engine import GcpIamEngine
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
        self._gcp_engine = GcpIamEngine(self._burp, config.gcp)
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

        # Phase 3b: GCP IAM tests
        if self._config.enable_gcp_tests:
            await self._run_gcp_tests()

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

    async def _run_gcp_tests(self) -> None:
        """Run GCP IAM privilege escalation tests."""
        primary = self._sessions[0] if self._sessions else UserSession(
            user_id="default", role="user"
        )
        logger.info("Running GCP IAM tests (project: %s)", self._config.gcp.project_id)
        try:
            gcp_findings = await self._gcp_engine.run(
                primary,
                target_url=self._config.target.base_url,
            )
            self._findings.extend(gcp_findings)
            if gcp_findings:
                logger.info("GCP IAM tests found %d issues", len(gcp_findings))
        except Exception as exc:
            logger.error("GCP IAM test error: %s", exc)

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


def build_parser() -> argparse.ArgumentParser:
    """Build the CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog="security-agent",
        description=(
            "Autonomous web application security research agent.\n"
            "Integrates with Burp Suite MCP to find vulnerabilities."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=_CLI_EPILOG,
    )

    subparsers = parser.add_subparsers(dest="command")

    # --- run (default) ---
    run_parser = subparsers.add_parser(
        "run",
        help="Start the security agent (default command)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    _add_run_args(run_parser)

    # --- init ---
    init_parser = subparsers.add_parser(
        "init",
        help="Generate a starter agent_config.json",
    )
    init_parser.add_argument(
        "--target", "-t",
        help="Target base URL to pre-fill",
        default="",
    )
    init_parser.add_argument(
        "--output", "-o",
        help="Output path (default: agent_config.json)",
        default="agent_config.json",
    )

    # --- validate ---
    validate_parser = subparsers.add_parser(
        "validate",
        help="Validate an existing config file",
    )
    validate_parser.add_argument(
        "validate_config",
        nargs="?",
        default="agent_config.json",
        help="Path to config file (default: agent_config.json)",
    )

    return parser


def _add_run_args(parser: argparse.ArgumentParser) -> None:
    """Add common run arguments to a parser."""
    parser.add_argument(
        "config",
        nargs="?",
        default=None,
        help="Path to config JSON file (default: auto-detect)",
    )
    parser.add_argument(
        "--target", "-t",
        help="Target base URL (overrides config)",
    )
    parser.add_argument(
        "--burp-url",
        help="Burp MCP server URL (default: http://localhost:9876)",
    )
    parser.add_argument(
        "--burp-proxy-port",
        type=int,
        help="Burp proxy port for browser traffic (default: 8080)",
    )
    parser.add_argument(
        "--headless/--no-headless",
        dest="headless",
        default=None,
        action=argparse.BooleanOptionalAction,
        help="Run browser in headless mode (default: true)",
    )
    parser.add_argument(
        "--h1-brain-url",
        help="h1-brain MCP server URL (enables h1-brain integration)",
    )
    parser.add_argument(
        "--program-handle",
        help="HackerOne program handle for h1-brain briefings",
    )
    parser.add_argument(
        "--no-recon",
        action="store_true",
        help="Skip recon phase",
    )
    parser.add_argument(
        "--no-injection",
        action="store_true",
        help="Skip injection testing phase",
    )
    parser.add_argument(
        "--gcp-project",
        help="GCP project ID for IAM testing (enables GCP tests)",
    )
    parser.add_argument(
        "--gcp-service-account",
        help="Target GCP service account email for impersonation tests",
    )
    parser.add_argument(
        "--no-gcp",
        action="store_true",
        help="Skip GCP IAM testing phase",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable debug logging",
    )


def _find_config_file() -> Path | None:
    """Auto-detect config file in common locations."""
    candidates = [
        Path("agent_config.json"),
        Path("config.json"),
        Path.home() / ".config" / "security-agent" / "config.json",
    ]
    for p in candidates:
        if p.exists():
            return p
    return None


def _resolve_config(args: argparse.Namespace) -> AgentConfig:
    """Build an AgentConfig from CLI args + env vars + config file."""
    # 1. Load from file (if provided or auto-detected)
    config_path = getattr(args, "config", None)
    if config_path:
        config = AgentConfig.from_file(config_path)
    else:
        found = _find_config_file()
        if found:
            logger.info("Using config: %s", found)
            config = AgentConfig.from_file(found)
        else:
            config = AgentConfig()

    # 2. Apply environment variable overrides
    config.apply_env_overrides()

    # 3. Apply CLI argument overrides (highest priority)
    target = getattr(args, "target", None)
    if target:
        config.target.base_url = target
        from urllib.parse import urlparse
        parsed = urlparse(target)
        if parsed.hostname and parsed.hostname not in config.target.allowed_domains:
            config.target.allowed_domains.append(parsed.hostname)

    burp_url = getattr(args, "burp_url", None)
    if burp_url:
        from urllib.parse import urlparse
        parsed = urlparse(burp_url)
        config.burp_mcp.host = parsed.hostname or "localhost"
        config.burp_mcp.port = parsed.port or 9876
        config.burp_mcp.use_ssl = parsed.scheme == "https"

    burp_proxy_port = getattr(args, "burp_proxy_port", None)
    if burp_proxy_port:
        config.browser.proxy_port = burp_proxy_port

    headless = getattr(args, "headless", None)
    if headless is not None:
        config.browser.headless = headless

    h1_brain_url = getattr(args, "h1_brain_url", None)
    if h1_brain_url:
        from urllib.parse import urlparse
        parsed = urlparse(h1_brain_url)
        config.h1_brain.host = parsed.hostname or "localhost"
        config.h1_brain.port = parsed.port or 3001
        config.h1_brain.enabled = True

    program_handle = getattr(args, "program_handle", None)
    if program_handle:
        config.target.program_handle = program_handle

    if getattr(args, "no_recon", False):
        config.enable_recon = False

    if getattr(args, "no_injection", False):
        config.enable_injection_tests = False

    gcp_project = getattr(args, "gcp_project", None)
    if gcp_project:
        config.gcp.project_id = gcp_project
        config.gcp.enabled = True
        config.enable_gcp_tests = True

    gcp_sa = getattr(args, "gcp_service_account", None)
    if gcp_sa:
        config.gcp.target_service_account = gcp_sa

    if getattr(args, "no_gcp", False):
        config.enable_gcp_tests = False

    return config


def _cmd_init(args: argparse.Namespace) -> None:
    """Handle the 'init' subcommand."""
    output = Path(args.output)
    if output.exists():
        print(f"⚠  {output} already exists. Overwrite? [y/N] ", end="")
        if input().strip().lower() != "y":
            print("Aborted.")
            return

    data = generate_default_config(
        target_url=args.target,
    )
    output.write_text(json.dumps(data, indent=2) + "\n")
    print(f"✅ Config written to {output}")
    print(f"   Edit it to set your target URL and session tokens.")
    print(f"   Then run: security-agent run")


def _cmd_validate(args: argparse.Namespace) -> None:
    """Handle the 'validate' subcommand."""
    path = Path(args.validate_config)
    if not path.exists():
        print(f"❌ Config file not found: {path}")
        sys.exit(1)
    try:
        config = AgentConfig.from_file(path)
    except Exception as exc:
        print(f"❌ Invalid config: {exc}")
        sys.exit(1)
    print(f"✅ Config is valid: {path}")
    if config.target.base_url:
        print(f"   Target: {config.target.base_url}")
    else:
        print(f"   ⚠  No target URL configured")
    print(f"   Burp MCP: {config.burp_mcp.base_url}")
    if config.h1_brain.enabled:
        print(f"   h1-brain: {config.h1_brain.base_url}")
    print(f"   Sessions: {len(config.user_sessions)}")


def _cmd_run(args: argparse.Namespace) -> None:
    """Handle the 'run' subcommand (or bare invocation)."""
    config = _resolve_config(args)

    if not config.target.base_url:
        print(
            "❌ No target URL configured.\n\n"
            "Set a target using any of these methods:\n"
            "  1. CLI flag:         security-agent run --target https://example.com\n"
            "  2. Environment var:  TARGET_URL=https://example.com security-agent\n"
            "  3. Config file:      security-agent init --target https://example.com\n"
        )
        sys.exit(1)

    logger.info("Target: %s", config.target.base_url)
    logger.info("Burp MCP: %s", config.burp_mcp.base_url)
    if config.h1_brain.enabled:
        logger.info("h1-brain: %s", config.h1_brain.base_url)
    if config.enable_gcp_tests:
        logger.info("GCP project: %s", config.gcp.project_id)
        if config.gcp.target_service_account:
            logger.info("GCP target SA: %s", config.gcp.target_service_account)

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


_CLI_EPILOG = """\
Quick start:
  security-agent run --target https://example.com
  security-agent init --target https://example.com
  TARGET_URL=https://example.com security-agent

GCP IAM testing:
  security-agent run --target https://example.com --gcp-project my-project
  security-agent run --gcp-project my-project --gcp-service-account sa@proj.iam.gserviceaccount.com

Environment variables:
  TARGET_URL          Target application URL
  BURP_MCP_URL        Burp MCP server URL (default: http://localhost:9876)
  BURP_MCP_HOST       Burp MCP host
  BURP_MCP_PORT       Burp MCP port
  BROWSER_PROXY_PORT  Burp proxy port for browser (default: 8080)
  H1_BRAIN_URL        h1-brain MCP server URL (enables integration)
  PROGRAM_HANDLE      HackerOne program handle
  HEADLESS            Browser headless mode (true/false)
  GCP_PROJECT         GCP project ID (enables GCP IAM tests)
  GCP_SERVICE_ACCOUNT Target SA email for impersonation tests
  GCP_KEY_FILE        Path to GCP service account key file
"""


def main() -> None:
    """CLI entry point."""
    # Backward compatibility: if the first arg looks like a file path
    # (not a known subcommand), treat it as: security-agent run <path>
    known_commands = {"run", "init", "validate"}
    argv = sys.argv[1:]
    if argv and argv[0] not in known_commands and not argv[0].startswith("-"):
        argv = ["run"] + argv

    parser = build_parser()
    args = parser.parse_args(argv)

    # Set up logging
    level = logging.DEBUG if getattr(args, "verbose", False) else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    # Route to the right subcommand
    command = args.command

    if command == "init":
        _cmd_init(args)
    elif command == "validate":
        _cmd_validate(args)
    elif command == "run":
        _cmd_run(args)
    else:
        # No subcommand — treat as 'run'
        _cmd_run(args)


if __name__ == "__main__":
    main()

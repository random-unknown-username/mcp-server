"""Tests for the CLI interface and config resolution."""

import json
import os
import tempfile
from pathlib import Path
from unittest import mock

from security_agent.config import AgentConfig, generate_default_config
from security_agent.main import build_parser, _resolve_config, _find_config_file


class TestEnvOverrides:
    """Test environment variable overrides on AgentConfig."""

    def test_target_url_override(self):
        config = AgentConfig()
        with mock.patch.dict(os.environ, {"TARGET_URL": "https://test.example.com"}):
            config.apply_env_overrides()
        assert config.target.base_url == "https://test.example.com"
        assert "test.example.com" in config.target.allowed_domains

    def test_burp_mcp_url_override(self):
        config = AgentConfig()
        with mock.patch.dict(os.environ, {"BURP_MCP_URL": "http://burp:1234"}):
            config.apply_env_overrides()
        assert config.burp_mcp.host == "burp"
        assert config.burp_mcp.port == 1234
        assert config.burp_mcp.use_ssl is False

    def test_burp_mcp_url_ssl(self):
        config = AgentConfig()
        with mock.patch.dict(os.environ, {"BURP_MCP_URL": "https://secure:443"}):
            config.apply_env_overrides()
        assert config.burp_mcp.use_ssl is True

    def test_burp_mcp_host_port_separate(self):
        config = AgentConfig()
        env = {"BURP_MCP_HOST": "remote", "BURP_MCP_PORT": "5555"}
        with mock.patch.dict(os.environ, env):
            config.apply_env_overrides()
        assert config.burp_mcp.host == "remote"
        assert config.burp_mcp.port == 5555

    def test_browser_proxy_port(self):
        config = AgentConfig()
        with mock.patch.dict(os.environ, {"BROWSER_PROXY_PORT": "9090"}):
            config.apply_env_overrides()
        assert config.browser.proxy_port == 9090

    def test_h1_brain_url_enables(self):
        config = AgentConfig()
        with mock.patch.dict(os.environ, {"H1_BRAIN_URL": "http://brain:4000"}):
            config.apply_env_overrides()
        assert config.h1_brain.enabled is True
        assert config.h1_brain.host == "brain"
        assert config.h1_brain.port == 4000

    def test_program_handle(self):
        config = AgentConfig()
        with mock.patch.dict(os.environ, {"PROGRAM_HANDLE": "my-prog"}):
            config.apply_env_overrides()
        assert config.target.program_handle == "my-prog"

    def test_headless_true(self):
        config = AgentConfig()
        with mock.patch.dict(os.environ, {"HEADLESS": "true"}):
            config.apply_env_overrides()
        assert config.browser.headless is True

    def test_headless_false(self):
        config = AgentConfig()
        with mock.patch.dict(os.environ, {"HEADLESS": "false"}):
            config.apply_env_overrides()
        assert config.browser.headless is False

    def test_no_env_vars_no_change(self):
        config = AgentConfig()
        # Clear relevant env vars
        clean_env = {
            k: v for k, v in os.environ.items()
            if k not in {
                "TARGET_URL", "BURP_MCP_URL", "BURP_MCP_HOST",
                "BURP_MCP_PORT", "BROWSER_PROXY_PORT", "H1_BRAIN_URL",
                "PROGRAM_HANDLE", "HEADLESS",
            }
        }
        with mock.patch.dict(os.environ, clean_env, clear=True):
            config.apply_env_overrides()
        assert config.target.base_url == ""
        assert config.burp_mcp.host == "localhost"


class TestGenerateDefaultConfig:
    """Test generate_default_config()."""

    def test_empty(self):
        data = generate_default_config()
        assert data["target"]["base_url"] == ""
        assert data["burp_mcp"]["port"] == 9876

    def test_with_target(self):
        data = generate_default_config(target_url="https://app.example.com")
        assert data["target"]["base_url"] == "https://app.example.com"
        assert "app.example.com" in data["target"]["allowed_domains"]


class TestBuildParser:
    """Test argparse CLI parser."""

    def test_help_does_not_crash(self):
        parser = build_parser()
        # Just ensure it builds without error
        assert parser is not None

    def test_run_with_target(self):
        parser = build_parser()
        args = parser.parse_args(["run", "--target", "https://example.com"])
        assert args.command == "run"
        assert args.target == "https://example.com"

    def test_run_with_all_flags(self):
        parser = build_parser()
        args = parser.parse_args([
            "run",
            "--target", "https://example.com",
            "--burp-url", "http://burp:1234",
            "--burp-proxy-port", "9090",
            "--h1-brain-url", "http://brain:3001",
            "--program-handle", "my-prog",
            "--no-recon",
            "--no-injection",
            "-v",
        ])
        assert args.target == "https://example.com"
        assert args.burp_url == "http://burp:1234"
        assert args.burp_proxy_port == 9090
        assert args.h1_brain_url == "http://brain:3001"
        assert args.program_handle == "my-prog"
        assert args.no_recon is True
        assert args.no_injection is True
        assert args.verbose is True

    def test_init_subcommand(self):
        parser = build_parser()
        args = parser.parse_args(["init", "--target", "https://example.com"])
        assert args.command == "init"
        assert args.target == "https://example.com"

    def test_validate_subcommand(self):
        parser = build_parser()
        args = parser.parse_args(["validate", "my_config.json"])
        assert args.command == "validate"
        assert args.validate_config == "my_config.json"

    def test_bare_config_file_backward_compat(self):
        """Backward compat is handled in main() via argv rewriting."""
        # build_parser() itself doesn't handle bare paths —
        # main() rewrites sys.argv before parsing.
        # Verify the 'run' subcommand accepts a positional config.
        parser = build_parser()
        args = parser.parse_args(["run", "my_config.json"])
        assert args.command == "run"
        assert args.config == "my_config.json"


class TestResolveConfig:
    """Test _resolve_config() merging CLI args + env + file."""

    def test_cli_target_overrides_file(self):
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False
        ) as f:
            json.dump({"target": {"base_url": "https://old.com"}}, f)
            f.flush()
            parser = build_parser()
            args = parser.parse_args([
                "run", f.name, "--target", "https://new.com"
            ])
            config = _resolve_config(args)
            assert config.target.base_url == "https://new.com"
            Path(f.name).unlink()

    def test_env_var_applied(self):
        parser = build_parser()
        args = parser.parse_args(["run"])
        with mock.patch.dict(os.environ, {"TARGET_URL": "https://env.com"}):
            config = _resolve_config(args)
        assert config.target.base_url == "https://env.com"

    def test_cli_overrides_env(self):
        parser = build_parser()
        args = parser.parse_args(["run", "--target", "https://cli.com"])
        with mock.patch.dict(os.environ, {"TARGET_URL": "https://env.com"}):
            config = _resolve_config(args)
        assert config.target.base_url == "https://cli.com"

    def test_burp_url_parsing(self):
        parser = build_parser()
        args = parser.parse_args([
            "run", "--target", "https://x.com",
            "--burp-url", "https://secure-burp:9999"
        ])
        config = _resolve_config(args)
        assert config.burp_mcp.host == "secure-burp"
        assert config.burp_mcp.port == 9999
        assert config.burp_mcp.use_ssl is True

    def test_no_recon_flag(self):
        parser = build_parser()
        args = parser.parse_args(["run", "--target", "https://x.com", "--no-recon"])
        config = _resolve_config(args)
        assert config.enable_recon is False

    def test_no_injection_flag(self):
        parser = build_parser()
        args = parser.parse_args([
            "run", "--target", "https://x.com", "--no-injection"
        ])
        config = _resolve_config(args)
        assert config.enable_injection_tests is False


class TestFindConfigFile:
    """Test auto-detection of config files."""

    def test_no_config_found(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        assert _find_config_file() is None

    def test_finds_agent_config(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        (tmp_path / "agent_config.json").write_text("{}")
        found = _find_config_file()
        assert found is not None
        assert found.name == "agent_config.json"

    def test_finds_config_json(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        (tmp_path / "config.json").write_text("{}")
        found = _find_config_file()
        assert found is not None
        assert found.name == "config.json"

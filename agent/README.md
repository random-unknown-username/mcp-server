# Autonomous Web Application Security Research Agent

An autonomous security research agent that integrates with the Burp Suite MCP Server to discover web application vulnerabilities. It operates like a real bug bounty researcher — performing recon, testing for injection flaws, access control issues, and business logic bugs, and optionally pulling intelligence from [h1-brain](https://github.com/PatrikFehrenbach/h1-brain) for HackerOne community insights.

## Quick Start

```bash
# 1. Install
cd agent
make setup             # or: pip install -e ".[dev]" && playwright install chromium

# 2. Run (pick one)
security-agent run --target https://your-target.com
TARGET_URL=https://your-target.com security-agent
security-agent run agent_config.json

# 3. Generate a config file (optional, for full customization)
security-agent init --target https://your-target.com
# Edit agent_config.json to add session tokens, then:
security-agent run
```

That's it. The agent will connect to Burp Suite MCP (default `localhost:9876`), launch a headless browser through Burp's proxy, and start finding vulnerabilities.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Security Agent (Python)                   │
│                                                             │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────┐  │
│  │   Browser     │  │  Burp MCP    │  │  Request Graph   │  │
│  │  Controller   │──│  Client      │──│  Builder         │  │
│  │ (Playwright)  │  │              │  │                  │  │
│  └──────────────┘  └──────────────┘  └──────────────────┘  │
│                                                             │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────┐  │
│  │  Recon       │  │  Injection   │  │  Vuln Knowledge  │  │
│  │  Engine      │  │  Test Engine │  │  Base (CWE)      │  │
│  └──────────────┘  └──────────────┘  └──────────────────┘  │
│                                                             │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────┐  │
│  │  Auth Test   │  │  Logic Test  │  │  Mutation         │  │
│  │  Engine      │  │  Engine      │  │  Engine           │  │
│  └──────────────┘  └──────────────┘  └──────────────────┘  │
│                                                             │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────┐  │
│  │  Response    │  │  Finding     │  │  Report           │  │
│  │  Analyzer    │  │  Verifier    │  │  Generator        │  │
│  └──────────────┘  └──────────────┘  └──────────────────┘  │
│                                                             │
│  ┌──────────────┐  ┌────────────────────────────────────┐  │
│  │  h1-brain    │  │    Main Agent Loop (24/7)           │  │
│  │  Client      │  │ recon→explore→test→inject→verify→  │  │
│  │  (optional)  │  │ report→repeat                      │  │
│  └──────────────┘  └────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
         │                      │                  │
         ▼                      ▼                  ▼
┌─────────────────┐   ┌─────────────────┐  ┌──────────────┐
│  Chromium        │   │  Burp Suite     │  │  h1-brain    │
│  (via Playwright)│──▶│  MCP Server     │  │  MCP Server  │
│                  │   │  (Kotlin ext)   │  │  (optional)  │
└─────────────────┘   └─────────────────┘  └──────────────┘
```

## What Makes This a Real Researcher

| Capability | Description |
|-----------|-------------|
| **Recon** | Tech fingerprinting, security header audit, interesting path discovery (/.env, /.git, /actuator, swagger, graphql, etc.) |
| **Injection Testing** | XSS, SQL injection, SSRF, SSTI, path traversal, open redirect, header injection — using real-world payloads |
| **Access Control** | IDOR, privilege escalation, auth bypass, horizontal/vertical access, JWT tampering (alg:none) |
| **Business Logic** | Workflow skip, negative values, replay attacks, race conditions, parameter pollution |
| **CORS Testing** | Tests CORS policies with evil origins and checks credential reflection |
| **Vulnerability KB** | Built-in CWE-mapped knowledge base with payloads and detection patterns |
| **h1-brain** | Optional integration with HackerOne disclosed reports and community weakness patterns |
| **Smart Targeting** | Suggests attack vectors per-endpoint based on parameter names and context |
| **Verification** | Multi-attempt reproducibility + cross-account validation |
| **Reporting** | JSON + Markdown reports with severity, reproduction steps, and PoC requests |

## Modules

| Module | Description |
|--------|-------------|
| `main.py` | Orchestrates the continuous agent loop with all phases |
| `recon_engine.py` | Tech fingerprinting, header audit, interesting path discovery, CORS probing |
| `vuln_knowledge.py` | CWE-mapped vulnerability knowledge base with payloads and detection patterns |
| `injection_test_engine.py` | Tests for XSS, SQLi, SSRF, SSTI, path traversal, open redirect, CORS, header injection |
| `h1_brain.py` | Client for h1-brain MCP server — attack briefings, disclosed reports, weakness patterns |
| `browser_controller.py` | Playwright-based browser automation with proxy support |
| `burp_mcp_client.py` | Client for the Burp Suite MCP server (request replay, history) |
| `request_graph_builder.py` | Builds endpoint/workflow graph from observed traffic |
| `mutation_engine.py` | Generates request mutations (ID swap, JWT tampering, auth removal) |
| `response_analyzer.py` | Differential response comparison to detect anomalies |
| `auth_test_engine.py` | Tests for IDOR, privilege escalation, broken access control |
| `logic_test_engine.py` | Tests for workflow bypass, race conditions, replay attacks |
| `finding_verifier.py` | Reproduces and cross-validates potential findings |
| `report_generator.py` | Generates JSON and Markdown vulnerability reports |
| `models.py` | Data models (requests, responses, findings, endpoints) |
| `config.py` | Configuration management |

## Setup

### Prerequisites

- Python 3.11+
- Burp Suite with the MCP Server extension installed and running
- (Optional) [h1-brain](https://github.com/PatrikFehrenbach/h1-brain) running for HackerOne intelligence

### Installation

```bash
cd agent

# Option A: One command
make setup

# Option B: Manual
pip install -e ".[dev]"
playwright install chromium
```

### Running

The agent supports three ways to configure it, in order of priority:

#### 1. CLI flags (simplest)
```bash
# Minimal — just a target URL (uses all defaults)
security-agent run --target https://your-target.com

# With all options
security-agent run \
  --target https://your-target.com \
  --burp-url http://localhost:9876 \
  --burp-proxy-port 8080 \
  --h1-brain-url http://localhost:3001 \
  --program-handle your-program \
  --no-headless \
  -v
```

#### 2. Environment variables
```bash
TARGET_URL=https://your-target.com security-agent
# or
export TARGET_URL=https://your-target.com
export BURP_MCP_URL=http://localhost:9876
export H1_BRAIN_URL=http://localhost:3001
export PROGRAM_HANDLE=your-program
security-agent
```

#### 3. Config file (full control)
```bash
# Generate a starter config
security-agent init --target https://your-target.com

# Edit it to add session tokens, excluded paths, etc.
vim agent_config.json

# Run with it
security-agent run agent_config.json
# or just: security-agent run  (auto-detects agent_config.json)
```

All three can be combined. CLI flags override env vars, which override the config file.

### Docker

```bash
# Build
make docker-build   # or: docker build -t security-agent .

# Run (Burp must be reachable from the container)
docker run --rm -it \
  -e TARGET_URL=https://your-target.com \
  -e BURP_MCP_HOST=host.docker.internal \
  -v ./reports:/app/reports \
  security-agent

# Or with docker-compose (includes optional h1-brain)
TARGET_URL=https://your-target.com docker compose up agent
```

### Makefile targets

```bash
make help        # Show all targets
make setup       # Install deps + Playwright
make run TARGET=https://example.com
make test        # Run tests
make init TARGET=https://example.com
make validate    # Validate config
make clean       # Remove state/reports/caches
```

### h1-brain Integration

To leverage HackerOne community intelligence:

```bash
# Quick: pass the URL and program handle
security-agent run \
  --target https://your-target.com \
  --h1-brain-url http://localhost:3001 \
  --program-handle your-program

# Or in config file, set:
#   h1_brain.enabled: true
#   target.program_handle: "your-program"

# Or with docker-compose (starts h1-brain automatically):
H1_API_TOKEN=your-token TARGET_URL=https://your-target.com \
  docker compose --profile h1-brain up
```

The agent will:
- Fetch an attack briefing with scope, past findings, and suggested vectors
- Pull publicly disclosed reports for the target program
- Use weakness patterns to prioritize testing

### Testing

```bash
cd agent
make test              # or: python -m pytest tests/ -v
```

### Environment Variables Reference

| Variable | Description | Default |
|----------|-------------|---------|
| `TARGET_URL` | Target application URL | (required) |
| `BURP_MCP_URL` | Full Burp MCP URL | `http://localhost:9876` |
| `BURP_MCP_HOST` | Burp MCP host | `localhost` |
| `BURP_MCP_PORT` | Burp MCP port | `9876` |
| `BROWSER_PROXY_PORT` | Burp proxy port for browser | `8080` |
| `H1_BRAIN_URL` | h1-brain URL (enables integration) | (disabled) |
| `PROGRAM_HANDLE` | HackerOne program handle | |
| `HEADLESS` | Browser headless mode | `true` |

## Agent Loop Phases

1. **Recon** — Fingerprint technologies, audit security headers, discover interesting paths, test CORS
2. **h1-brain Briefing** — Fetch attack briefing and disclosed reports (if configured)
3. **Explore** — Browser crawl + Burp proxy history ingestion
4. **Auth/Access Tests** — IDOR, privilege escalation, auth bypass, horizontal access
5. **Injection Tests** — XSS, SQLi, SSRF, SSTI, path traversal, open redirect, CORS, header injection
6. **Verify** — Multi-attempt reproducibility + cross-account validation
7. **Report** — Generate JSON + Markdown reports
8. **Repeat** — Loop every 30 seconds

## Safety

The agent only operates on targets configured in `allowed_domains`. All traffic is proxied through Burp Suite for full visibility and control.

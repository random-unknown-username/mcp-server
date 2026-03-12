# Autonomous Web Application Security Research Agent

An autonomous security research agent that integrates with the Burp Suite MCP Server to discover web application vulnerabilities, focusing on authentication flaws, authorization bypass, and business logic issues.

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
│  │  Auth Test   │  │  Logic Test  │  │  Mutation         │  │
│  │  Engine      │  │  Engine      │  │  Engine           │  │
│  └──────────────┘  └──────────────┘  └──────────────────┘  │
│                                                             │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────┐  │
│  │  Response    │  │  Finding     │  │  Report           │  │
│  │  Analyzer    │  │  Verifier    │  │  Generator        │  │
│  └──────────────┘  └──────────────┘  └──────────────────┘  │
│                                                             │
│  ┌─────────────────────────────────────────────────────┐    │
│  │              Main Agent Loop (24/7)                  │    │
│  │   explore → test → verify → report → repeat         │    │
│  └─────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────┘
         │                      │
         ▼                      ▼
┌─────────────────┐   ┌─────────────────┐
│  Chromium        │   │  Burp Suite     │
│  (via Playwright)│──▶│  MCP Server     │
│                  │   │  (Kotlin ext)   │
└─────────────────┘   └─────────────────┘
```

## Data Flow

```
Browser crawl ──► Burp Proxy ──► Request Graph ──► Test Engines
                                                        │
                    ┌───────────────────────────────────┘
                    ▼
              Mutation Engine ──► Burp MCP (replay) ──► Response Analyzer
                                                              │
                                                              ▼
                                                       Finding Verifier
                                                              │
                                                              ▼
                                                       Report Generator
                                                        (JSON + Markdown)
```

## Modules

| Module | Description |
|--------|-------------|
| `browser_controller.py` | Playwright-based browser automation with proxy support |
| `burp_mcp_client.py` | Client for the Burp Suite MCP server (request replay, history) |
| `request_graph_builder.py` | Builds endpoint/workflow graph from observed traffic |
| `mutation_engine.py` | Generates request mutations (ID swap, JWT tampering, auth removal) |
| `response_analyzer.py` | Differential response comparison to detect anomalies |
| `auth_test_engine.py` | Tests for IDOR, privilege escalation, broken access control |
| `logic_test_engine.py` | Tests for workflow bypass, race conditions, replay attacks |
| `finding_verifier.py` | Reproduces and cross-validates potential findings |
| `report_generator.py` | Generates JSON and Markdown vulnerability reports |
| `main.py` | Orchestrates the continuous agent loop |
| `models.py` | Data models (requests, responses, findings, endpoints) |
| `config.py` | Configuration management |

## Core Algorithms

### IDOR Detection
1. Parse numeric/UUID IDs from URL paths and request bodies
2. Generate mutations: increment IDs, swap with known IDs, use cross-account IDs
3. Replay mutated requests via Burp MCP
4. Compare responses for data leakage indicators

### Auth Bypass Detection
1. Strip authentication headers/cookies from authenticated requests
2. Tamper with JWT claims (role escalation, alg:none)
3. Swap session tokens between user accounts
4. Detect unexpected success responses (403→200 transitions)

### Business Logic Testing
1. Skip steps in multi-step workflows (access final step directly)
2. Inject negative/zero values in numeric fields (price, quantity)
3. Replay identical requests to detect missing idempotency controls
4. Fire concurrent requests to detect race conditions

### Differential Response Analysis
1. Compare status codes (detect unexpected success)
2. Measure body size changes (>30% flagged)
3. Diff JSON fields (detect new sensitive fields)
4. Scan for error message indicators (stack traces, SQL errors)

## Setup

### Prerequisites

- Python 3.11+
- Burp Suite with the MCP Server extension installed and running
- Playwright browsers installed

### Installation

```bash
cd agent
pip install -e ".[dev]"
playwright install chromium
```

### Configuration

Create `agent_config.json`:

```json
{
  "target": {
    "base_url": "https://target-app.example.com",
    "allowed_domains": ["target-app.example.com"]
  },
  "burp_mcp": {
    "host": "localhost",
    "port": 9876
  },
  "browser": {
    "headless": true,
    "proxy_host": "localhost",
    "proxy_port": 8080
  },
  "max_concurrent_tests": 5,
  "user_sessions": [
    {
      "user_id": "user_a",
      "role": "user",
      "headers": {"Authorization": "Bearer <token_a>"},
      "cookies": {"session": "<session_a>"}
    },
    {
      "user_id": "user_b",
      "role": "user",
      "headers": {"Authorization": "Bearer <token_b>"},
      "cookies": {"session": "<session_b>"}
    }
  ]
}
```

### Running

```bash
# Continuous operation (24/7)
security-agent agent_config.json

# Or via Python
python -m security_agent.main agent_config.json
```

### Testing

```bash
cd agent
python -m pytest tests/ -v
```

## Safety

The agent only operates on targets configured in `allowed_domains`. All traffic is proxied through Burp Suite for full visibility and control.

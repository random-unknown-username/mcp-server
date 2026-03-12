# Autonomous Web Application Security Research Agent

An autonomous security research agent that integrates with the Burp Suite MCP Server to discover web application vulnerabilities. It operates like a real bug bounty researcher — performing recon, testing for injection flaws, access control issues, and business logic bugs, and optionally pulling intelligence from [h1-brain](https://github.com/PatrikFehrenbach/h1-brain) for HackerOne community insights.

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
- Playwright browsers installed
- (Optional) [h1-brain](https://github.com/PatrikFehrenbach/h1-brain) running for HackerOne intelligence

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
    "allowed_domains": ["target-app.example.com"],
    "program_handle": "target-program"
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
  "h1_brain": {
    "host": "localhost",
    "port": 3001,
    "enabled": false
  },
  "enable_injection_tests": true,
  "enable_recon": true,
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

### h1-brain Integration

To leverage HackerOne community intelligence:

1. Set up [h1-brain](https://github.com/PatrikFehrenbach/h1-brain) with your HackerOne API credentials
2. Run the h1-brain server
3. Set `h1_brain.enabled: true` and configure host/port in your agent config
4. Set `target.program_handle` to the HackerOne program handle

The agent will:
- Fetch an attack briefing with scope, past findings, and suggested vectors
- Pull publicly disclosed reports for the target program
- Use weakness patterns to prioritize testing

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

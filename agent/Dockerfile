FROM python:3.12-slim

# Install system dependencies for Playwright
RUN apt-get update && apt-get install -y --no-install-recommends \
    libnss3 libatk1.0-0 libatk-bridge2.0-0 libcups2 libdrm2 \
    libxkbcommon0 libxcomposite1 libxdamage1 libxrandr2 libgbm1 \
    libpango-1.0-0 libcairo2 libasound2 libxshmfence1 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python package
COPY pyproject.toml .
COPY security_agent/ security_agent/
RUN pip install --no-cache-dir -e .

# Install Playwright browsers
RUN playwright install chromium --with-deps

# Create output directories
RUN mkdir -p /app/reports /app/agent_state

VOLUME ["/app/reports", "/app/agent_state"]

ENTRYPOINT ["security-agent"]
CMD ["run"]

"""Browser automation layer using Playwright.

Provides capabilities for login flows, cookie/session handling,
form submission, navigation discovery, DOM inspection, token extraction,
SPA interaction, and JavaScript execution monitoring.
All traffic is proxied through Burp Suite.
"""

from __future__ import annotations

import logging
import re
from typing import Any

from playwright.async_api import Browser, BrowserContext, Page, async_playwright

from .config import BrowserConfig

logger = logging.getLogger(__name__)


class BrowserController:
    """Manages a Playwright browser instance that proxies through Burp."""

    def __init__(self, config: BrowserConfig) -> None:
        self._config = config
        self._playwright: Any = None
        self._browser: Browser | None = None
        self._context: BrowserContext | None = None
        self._page: Page | None = None

    async def start(self) -> None:
        self._playwright = await async_playwright().start()
        self._browser = await self._playwright.chromium.launch(
            headless=self._config.headless,
            proxy={"server": self._config.proxy_url},
        )
        self._context = await self._browser.new_context(
            viewport={
                "width": self._config.viewport_width,
                "height": self._config.viewport_height,
            },
            ignore_https_errors=True,
        )
        self._page = await self._context.new_page()
        logger.info(
            "Browser started (headless=%s, proxy=%s)",
            self._config.headless,
            self._config.proxy_url,
        )

    async def stop(self) -> None:
        if self._browser:
            await self._browser.close()
        if self._playwright:
            await self._playwright.stop()
        self._browser = None
        self._context = None
        self._page = None

    @property
    def page(self) -> Page:
        if self._page is None:
            raise RuntimeError("Browser not started. Call start() first.")
        return self._page

    async def navigate(self, url: str) -> str:
        resp = await self.page.goto(
            url, wait_until="domcontentloaded",
            timeout=self._config.timeout_ms,
        )
        status = resp.status if resp else 0
        logger.debug("Navigated to %s (status=%d)", url, status)
        return await self.page.content()

    async def get_cookies(self) -> list[dict[str, Any]]:
        if self._context is None:
            return []
        return await self._context.cookies()

    async def set_cookies(self, cookies: list[dict[str, Any]]) -> None:
        if self._context:
            await self._context.add_cookies(cookies)

    async def extract_links(self) -> list[str]:
        return await self.page.eval_on_selector_all(
            "a[href]",
            "elements => elements.map(e => e.href)",
        )

    async def extract_forms(self) -> list[dict[str, Any]]:
        return await self.page.evaluate("""() => {
            return Array.from(document.forms).map(form => ({
                action: form.action,
                method: form.method,
                inputs: Array.from(form.elements).map(el => ({
                    name: el.name,
                    type: el.type,
                    value: el.value,
                })).filter(el => el.name),
            }));
        }""")

    async def extract_tokens(self) -> dict[str, str]:
        tokens: dict[str, str] = {}
        meta_tokens = await self.page.evaluate("""() => {
            const meta = document.querySelector('meta[name="csrf-token"]');
            return meta ? meta.getAttribute('content') : null;
        }""")
        if meta_tokens:
            tokens["csrf-token"] = meta_tokens

        hidden_inputs = await self.page.eval_on_selector_all(
            'input[type="hidden"]',
            """elements => elements.map(e => ({name: e.name, value: e.value}))""",
        )
        for inp in hidden_inputs:
            if inp["name"] and inp["value"]:
                tokens[inp["name"]] = inp["value"]

        return tokens

    async def extract_js_endpoints(self) -> list[str]:
        scripts = await self.page.evaluate("""() => {
            return Array.from(document.scripts)
                .map(s => s.src || s.textContent)
                .filter(Boolean);
        }""")
        endpoints: list[str] = []
        api_pattern = re.compile(r'["\'](/api/[^\s"\']+)["\']')
        url_pattern = re.compile(r'["\']((https?://)[^\s"\']+)["\']')
        for script in scripts:
            endpoints.extend(api_pattern.findall(str(script)))
            endpoints.extend(m[0] for m in url_pattern.findall(str(script)))
        return list(set(endpoints))

    async def submit_form(
        self, selector: str, data: dict[str, str]
    ) -> str:
        for field_name, value in data.items():
            await self.page.fill(f'{selector} [name="{field_name}"]', value)
        await self.page.click(f'{selector} [type="submit"]')
        await self.page.wait_for_load_state("domcontentloaded")
        return await self.page.content()

    async def execute_js(self, script: str) -> Any:
        return await self.page.evaluate(script)

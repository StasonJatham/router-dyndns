from __future__ import annotations

import asyncio
import contextlib
import html
import secrets
import sqlite3
import urllib.parse
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Annotated

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request, Response
from fastapi.responses import FileResponse, HTMLResponse, PlainTextResponse, RedirectResponse
from starlette.concurrency import run_in_threadpool
from starlette.middleware.trustedhost import TrustedHostMiddleware
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from .ddns_api import create_api_router
from .ddns_dns import delete_dns_records, dns_backend_configured, publish_dns
from .ddns_models import DdnsSettings, UpdateResult
from .ddns_security import (
    admin_csrf_token,
    client_ip,
    credentials_from_basic_auth,
    is_rate_limited_path,
    rate_limit_bucket,
    require_admin_csrf,
)
from .ddns_service import DdnsService, normalize_domain, normalize_hostname
from .ddns_store import DdnsStore

__all__ = [
    "DdnsSettings",
    "DdnsStore",
    "UpdateResult",
    "delete_dns_records",
    "make_app",
    "publish_dns",
]


OPENAPI_TAGS = [
    {
        "name": "hostnames",
        "description": "Create provider-owned or verified custom DynDNS hostnames.",
    },
    {
        "name": "domains",
        "description": "Issue and verify DNS TXT challenges for custom domains.",
    },
    {
        "name": "updates",
        "description": "Router-facing IP update endpoints for FRITZ!Box and compatible clients.",
    },
    {
        "name": "management",
        "description": "Bearer-link management for generated hostnames.",
    },
]

ASSET_DIR = Path(__file__).with_name("assets")

APP_JS = """
(() => {
  const applyTheme = () => {
    const theme = window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
    document.documentElement.setAttribute("data-bs-theme", theme);
    document.documentElement.style.colorScheme = theme;
  };
  applyTheme();
  window.matchMedia("(prefers-color-scheme: dark)").addEventListener("change", applyTheme);
})();

document.addEventListener("click", async (event) => {
  const button = event.target.closest("[data-copy]");
  if (!button) return;
  try {
    await navigator.clipboard.writeText(button.dataset.copy || "");
    const old = button.textContent;
    button.textContent = "Copied";
    setTimeout(() => {
      button.textContent = old;
    }, 1200);
  } catch (_) {}
});
""".strip()


class RequestBodyTooLargeError(Exception):
    pass


class RequestBodyLimitMiddleware:
    def __init__(self, app: ASGIApp, max_body_bytes: int) -> None:
        self.app = app
        self.max_body_bytes = max_body_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        received = 0

        async def limited_receive() -> Message:
            nonlocal received
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > self.max_body_bytes:
                    raise RequestBodyTooLargeError
            return message

        try:
            await self.app(scope, limited_receive, send)
        except RequestBodyTooLargeError:
            response = PlainTextResponse("request body too large", status_code=413)
            await response(scope, receive, send)


def make_app(settings: DdnsSettings | None = None) -> FastAPI:
    settings = settings or DdnsSettings.from_env()
    if not settings.admin_password and settings.shared_secret:
        settings = settings.model_copy(update={"admin_password": settings.shared_secret})
    if settings.require_dns_provider and not dns_backend_configured(settings):
        raise RuntimeError("DDNS_REQUIRE_DNS_PROVIDER is set but no DNS backend is configured")
    settings.validate_launch_ready()

    store = DdnsStore(settings.database_path)
    store.cleanup(settings.cleanup_challenge_hours, settings.cleanup_unused_account_hours)
    service = DdnsService(settings, store)

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        cleanup_task = asyncio.create_task(_cleanup_loop(store, settings))
        try:
            yield
        finally:
            cleanup_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await cleanup_task

    app = FastAPI(
        title="router_dyndns DDNS",
        summary="A small self-hosted DynDNS provider for FRITZ!Box routers.",
        description=(
            "Generate cryptographically random DynDNS endpoints, verify custom domains with DNS TXT "
            "records, and publish A/AAAA records through Cloudflare or RFC 2136."
        ),
        version="0.1.0",
        docs_url="/docs",
        redoc_url="/redoc",
        openapi_tags=OPENAPI_TAGS,
        lifespan=lifespan,
    )
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=settings.effective_trusted_hosts)
    app.add_middleware(RequestBodyLimitMiddleware, max_body_bytes=settings.max_request_body_bytes)
    app.include_router(create_api_router(settings, store, service))

    @app.middleware("http")
    async def security_middleware(request: Request, call_next):
        try:
            content_length = int(request.headers.get("content-length", "0") or "0")
        except ValueError:
            content_length = 0
        if content_length > settings.max_request_body_bytes:
            return PlainTextResponse("request body too large", status_code=413)

        if is_rate_limited_path(request.url.path) or _is_admin_path(request.url.path):
            limit = settings.admin_rate_limit_per_minute if _is_admin_path(request.url.path) else settings.rate_limit_per_minute
            key = f"{client_ip(request, settings)}:{rate_limit_bucket(request.url.path)}"
            allowed = await run_in_threadpool(store.allow_rate_limit, key, limit)
            if not allowed:
                return PlainTextResponse("rate limit exceeded", status_code=429)

        response = await call_next(request)
        if _is_secret_response(request):
            response.headers["Cache-Control"] = "no-store"
            response.headers["Pragma"] = "no-cache"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "same-origin"
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
        response.headers["Content-Security-Policy"] = _content_security_policy(request.url.path)
        if settings.public_base_url.startswith("https://"):
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        return response

    def authenticate_update(
        authorization: Annotated[str | None, Header()] = None,
        username: str | None = Query(default=None),
        password: str | None = Query(default=None),
        pass_: str | None = Query(default=None, alias="pass"),
        passwd: str | None = Query(default=None),
    ) -> tuple[str | None, str | None]:
        supplied_user = username
        supplied_token = password or pass_ or passwd
        if authorization and authorization.lower().startswith("basic "):
            supplied_user, supplied_token = credentials_from_basic_auth(authorization)
        return supplied_user, supplied_token

    def authenticate_admin(
        authorization: Annotated[str | None, Header()] = None,
    ) -> None:
        if not settings.admin_password:
            raise HTTPException(status_code=500, detail="DDNS_ADMIN_PASSWORD is required")

        supplied = None
        if authorization and authorization.lower().startswith("basic "):
            _, supplied = credentials_from_basic_auth(authorization)

        if not supplied or not secrets.compare_digest(supplied, settings.admin_password):
            raise HTTPException(
                status_code=401,
                detail="admin authentication required",
                headers={"WWW-Authenticate": 'Basic realm="router_dyndns-ddns"'},
            )

    def apply_update(
        request: Request,
        hostname: str,
        myip: str | None,
        ipaddr: str | None,
        myipv6: str | None,
        ip6addr: str | None,
    ) -> str | PlainTextResponse:
        try:
            return service.apply_update(request, hostname, myip, ipaddr, myipv6, ip6addr).result.dyndns_response
        except Exception:
            return PlainTextResponse("911 dns publish failed", status_code=500)

    @app.get("/", response_class=HTMLResponse)
    def index() -> str:
        return _render_public_home(service, settings, None, None)

    @app.post("/magic", response_class=HTMLResponse)
    async def magic_account(request: Request) -> str:
        form = await _request_form(request, settings)
        username = _first_form_value(form, "username") or None
        account = await run_in_threadpool(service.create_managed_account, username)
        return _render_public_home(service, settings, account, None)

    @app.get("/m/{management_slug}", response_class=HTMLResponse)
    def manage_magic(management_slug: str) -> str:
        account = store.get_account_by_management_slug(management_slug)
        if not account or account["disabled"]:
            raise HTTPException(status_code=404, detail="not found")
        return _render_management_page(service, settings, management_slug, account)

    @app.get("/d/{claim_secret}", response_class=HTMLResponse)
    def manage_domain_claim(claim_secret: str) -> str:
        challenge = store.get_domain_challenge_by_secret(claim_secret)
        if not challenge:
            raise HTTPException(status_code=404, detail="not found")
        return _render_public_home(service, settings, None, None, challenge)

    @app.post("/m/{management_slug}/delete")
    def delete_magic(management_slug: str) -> Response:
        account = store.get_account_by_management_slug(management_slug)
        if not account or account["disabled"]:
            raise HTTPException(status_code=404, detail="not found")
        hostname = str(account["hostname"])
        try:
            service.delete_account(hostname, "management-link")
        except Exception:
            return PlainTextResponse("DNS delete failed; hostname was not deleted", status_code=500)
        return HTMLResponse(
            _page(
                "DynDNS deleted",
                """
                <main>
                  <section class="hero-band compact">
                    <div class="container hero-inner">
                      <p class="eyebrow">Deleted</p>
                      <h1>Hostname deleted.</h1>
                      <p class="lead">The update URL no longer works.</p>
                      <a class="btn btn-outline-primary rounded-pill" href="/">Home</a>
                    </div>
                  </section>
                </main>
                """,
            )
        )

    @app.post("/request-domain", response_class=HTMLResponse)
    async def request_domain(request: Request) -> str:
        form = await _request_form(request, settings)
        try:
            challenge = await run_in_threadpool(
                service.create_domain_challenge,
                _first_form_value(form, "domain"),
            )
        except sqlite3.IntegrityError as exc:
            raise HTTPException(status_code=409, detail="domain is already verified") from exc
        return _render_public_home(service, settings, None, None, challenge)

    @app.post("/verify-domain", response_class=HTMLResponse)
    async def verify_domain(request: Request) -> str:
        form = await _request_form(request, settings)
        domain = normalize_domain(_first_form_value(form, "domain"))
        claim_secret = _first_form_value(form, "claim_secret")
        found, challenge = await run_in_threadpool(service.verify_domain, domain, claim_secret)
        if not found:
            message = "TXT record not found yet. DNS propagation can take a few minutes."
            return _render_public_home(service, settings, None, message, challenge)
        return _render_public_home(service, settings, None, "Domain verified. You can now create a hostname under it.", challenge)

    @app.post("/accounts", response_class=HTMLResponse)
    async def self_service_account(request: Request) -> str:
        form = await _request_form(request, settings)
        mode = _first_form_value(form, "mode")
        username = _first_form_value(form, "username") or None
        if mode == "managed":
            account = await run_in_threadpool(service.create_managed_account, username)
        else:
            claim_secret = _first_form_value(form, "claim_secret")
            account = await run_in_threadpool(
                service.create_custom_account,
                _first_form_value(form, "hostname"),
                claim_secret,
                username,
            )
        return _render_public_home(service, settings, account, None)

    @app.get("/admin", response_class=HTMLResponse, include_in_schema=False)
    def admin(_: None = Depends(authenticate_admin)) -> str:
        return _render_admin_page(
            service,
            settings,
            store.list_accounts(),
            store.list_domain_challenges(),
            store.list_cleanup_runs(),
            store.list_update_events(25),
            None,
            None,
        )

    @app.post("/admin/accounts", include_in_schema=False)
    async def admin_create_account(request: Request, _: None = Depends(authenticate_admin)) -> Response:
        form = await _request_form(request, settings)
        require_admin_csrf(settings, _first_form_value(form, "csrf"))
        hostname = normalize_hostname(_first_form_value(form, "hostname"), settings)
        username = _first_form_value(form, "username") or None
        if not hostname:
            raise HTTPException(status_code=400, detail="hostname is required")
        if settings.allowed_hosts and hostname not in settings.allowed_hosts:
            raise HTTPException(status_code=403, detail="hostname is not allowed")
        try:
            account = store.create_account(hostname, username)
        except sqlite3.IntegrityError as exc:
            raise HTTPException(status_code=409, detail="hostname already exists") from exc
        return HTMLResponse(
            _render_admin_page(
                service,
                settings,
                store.list_accounts(),
                store.list_domain_challenges(),
                store.list_cleanup_runs(),
                store.list_update_events(25),
                account,
                None,
            )
        )

    @app.post("/admin/accounts/delete", include_in_schema=False)
    async def admin_delete_account(request: Request, _: None = Depends(authenticate_admin)) -> Response:
        form = await _request_form(request, settings)
        require_admin_csrf(settings, _first_form_value(form, "csrf"))
        hostname = _first_form_value(form, "hostname")
        if hostname:
            try:
                service.delete_account(hostname, "admin")
            except Exception:
                return PlainTextResponse("DNS delete failed; hostname was not deleted", status_code=500)
        return RedirectResponse("/admin", status_code=303)

    @app.post("/admin/accounts/rotate", include_in_schema=False)
    async def admin_rotate_account(request: Request, _: None = Depends(authenticate_admin)) -> Response:
        form = await _request_form(request, settings)
        require_admin_csrf(settings, _first_form_value(form, "csrf"))
        hostname = normalize_hostname(_first_form_value(form, "hostname"), settings, expand_suffix=False)
        action = _first_form_value(form, "action")
        account = store.get_account_by_hostname(hostname)
        if not account:
            raise HTTPException(status_code=404, detail="hostname not found")

        notice = None
        if action == "update":
            rotated = store.rotate_update_slug(hostname)
            notice = _admin_secret_panel("Update URL rotated", [_copy_row("Update-URL:", service.fritz_update_url(rotated))]) if rotated else None
        elif action == "management":
            rotated = store.rotate_management_slug(hostname)
            notice = _admin_secret_panel("Private status page rotated", [_copy_row("Private status page:", service.magic_management_url(rotated))]) if rotated else None
        elif action == "password":
            rotated = store.rotate_password(hostname)
            if rotated:
                notice = _admin_secret_panel(
                    "Router password rotated",
                    [
                        _copy_row("Domainnamen:", str(rotated["hostname"])),
                        _copy_row("Benutzername:", str(rotated["username"])),
                        _copy_row("Kennwort:", str(rotated["password"])),
                    ],
                )
        else:
            raise HTTPException(status_code=400, detail="invalid rotation action")
        return HTMLResponse(
            _render_admin_page(
                service,
                settings,
                store.list_accounts(),
                store.list_domain_challenges(),
                store.list_cleanup_runs(),
                store.list_update_events(25),
                None,
                notice,
            )
        )

    @app.post("/admin/cleanup", include_in_schema=False)
    async def admin_run_cleanup(request: Request, _: None = Depends(authenticate_admin)) -> Response:
        form = await _request_form(request, settings)
        require_admin_csrf(settings, _first_form_value(form, "csrf"))
        result = await run_in_threadpool(store.cleanup, settings.cleanup_challenge_hours, settings.cleanup_unused_account_hours)
        notice = _admin_secret_panel(
            "Cleanup completed",
            [
                _copy_row("Domain claims removed", str(result["domain_challenges"])),
                _copy_row("Unused hostnames removed", str(result["unused_accounts"])),
            ],
        )
        return HTMLResponse(
            _render_admin_page(
                service,
                settings,
                store.list_accounts(),
                store.list_domain_challenges(),
                store.list_cleanup_runs(),
                store.list_update_events(25),
                None,
                notice,
            )
        )

    @app.get("/records", include_in_schema=False)
    def records(_: None = Depends(authenticate_admin)) -> list[dict[str, str | None]]:
        return store.list_records()

    @app.get("/events", include_in_schema=False)
    def events(_: None = Depends(authenticate_admin)) -> list[dict[str, str | None]]:
        return store.list_update_events()

    @app.get("/healthz", response_class=PlainTextResponse)
    def healthz() -> str:
        return "ok"

    @app.get("/favicon.ico", include_in_schema=False)
    def favicon() -> FileResponse:
        return FileResponse(ASSET_DIR / "favicon.ico", media_type="image/x-icon")

    @app.get("/logo.svg", include_in_schema=False)
    def logo_svg() -> FileResponse:
        return FileResponse(ASSET_DIR / "logo.svg", media_type="image/svg+xml")

    @app.get("/logo.png", include_in_schema=False)
    def logo_png() -> FileResponse:
        return FileResponse(ASSET_DIR / "logo.png", media_type="image/png")

    @app.get("/app.js", include_in_schema=False)
    def app_js() -> Response:
        return Response(APP_JS, media_type="application/javascript")

    @app.get("/u/{update_slug}", response_class=PlainTextResponse, response_model=None)
    def slug_update(
        update_slug: str,
        request: Request,
        myip: str | None = Query(default=None),
        ipaddr: str | None = Query(default=None),
        myipv6: str | None = Query(default=None),
        ip6addr: str | None = Query(default=None),
    ) -> str | PlainTextResponse:
        account = store.get_account_by_slug(update_slug)
        if not account or account["disabled"]:
            raise HTTPException(status_code=404, detail="not found")
        return apply_update(request, str(account["hostname"]), myip, ipaddr, myipv6, ip6addr)

    @app.get("/nic/update", response_class=PlainTextResponse, response_model=None)
    def update(
        request: Request,
        credentials: tuple[str | None, str | None] = Depends(authenticate_update),
        hostname: str | None = Query(default=None),
        domain: str | None = Query(default=None),
        myip: str | None = Query(default=None),
        ipaddr: str | None = Query(default=None),
        myipv6: str | None = Query(default=None),
        ip6addr: str | None = Query(default=None),
    ) -> str | PlainTextResponse:
        host = (hostname or domain or "").strip().lower().rstrip(".")
        if not host:
            return PlainTextResponse("nohost", status_code=400)
        if settings.allowed_hosts and host not in settings.allowed_hosts:
            return PlainTextResponse("nohost", status_code=403)
        supplied_user, supplied_token = credentials
        global_secret_ok = settings.shared_secret and supplied_token and secrets.compare_digest(supplied_token, settings.shared_secret)
        if not global_secret_ok and not store.verify_account(host, supplied_user, supplied_token):
            return PlainTextResponse("badauth", status_code=401)
        return apply_update(request, host, myip, ipaddr, myipv6, ip6addr)

    return app


async def _cleanup_loop(store: DdnsStore, settings: DdnsSettings) -> None:
    while True:
        await asyncio.sleep(settings.cleanup_interval_seconds)
        await run_in_threadpool(
            store.cleanup,
            settings.cleanup_challenge_hours,
            settings.cleanup_unused_account_hours,
        )


def _parse_form(body: bytes) -> dict[str, list[str]]:
    return urllib.parse.parse_qs(body.decode("utf-8"), keep_blank_values=True)


async def _request_form(request: Request, settings: DdnsSettings) -> dict[str, list[str]]:
    body = await request.body()
    if len(body) > settings.max_request_body_bytes:
        raise HTTPException(status_code=413, detail="request body too large")
    return _parse_form(body)


def _first_form_value(form: dict[str, list[str]], key: str) -> str:
    return form.get(key, [""])[0].strip()


def _is_admin_path(path: str) -> bool:
    return path == "/admin" or path.startswith("/admin/") or path in {"/records", "/events"}


def _is_secret_response(request: Request) -> bool:
    path = request.url.path
    if _is_admin_path(path) or path.startswith(("/m/", "/d/")):
        return True
    if path.startswith(("/api/v1/hostnames/", "/api/v1/domains/")):
        return request.method in {"POST", "DELETE"}
    return request.method == "POST" and path in {"/magic", "/request-domain", "/verify-domain", "/accounts"}


def _content_security_policy(path: str) -> str:
    if path in {"/docs", "/redoc", "/openapi.json"}:
        return (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
            "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
            "img-src 'self' data: https://fastapi.tiangolo.com; "
            "font-src 'self' https://cdn.jsdelivr.net; "
            "connect-src 'self'; "
            "form-action 'self'; "
            "frame-ancestors 'none'"
        )
    return (
        "default-src 'self'; "
        "script-src 'self'; "
        "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
        "img-src 'self' data:; "
        "font-src 'self' https://cdn.jsdelivr.net; "
        "connect-src 'self'; "
        "form-action 'self'; "
        "frame-ancestors 'none'"
    )


def _render_public_home(
    service: DdnsService,
    settings: DdnsSettings,
    created_account: dict[str, str] | None,
    message: str | None,
    challenge: dict[str, str | None] | None = None,
) -> str:
    suffix = html.escape(settings.hostname_suffix or "your DynDNS domain")
    created_html = _credentials_panel(service, created_account)
    message_html = _message_band(message) if message and not challenge else ""
    challenge_html = _custom_domain_flow(service, challenge, message)
    return _page(
        "router-dyndns",
        f"""
        <main id="main">
          {_top_nav()}
          <section class="hero-band">
            <div class="container hero-inner">
              <p class="eyebrow">FRITZ!Box compatible</p>
              <h1>DynDNS without signups.</h1>
              <p class="lead">Create a secure update endpoint under {suffix}. Provider hostnames are anonymous; custom domains require DNS proof.</p>
              <div class="hero-actions">
                <a class="btn btn-primary rounded-pill" href="#create">Get a hostname</a>
                <a class="btn btn-outline-primary rounded-pill" href="#custom-domain">Verify a domain</a>
              </div>
            </div>
          </section>
          {message_html}
          {created_html}
          <section class="section" id="create">
            <div class="container tool-grid">
              <div>
                <p class="eyebrow">Free DynDNS hostname</p>
                <h2>Create a router update URL</h2>
                <p class="section-copy">Generate a random hostname, paste the update URL into your router, and keep the management link private.</p>
              </div>
              <form method="post" action="/magic" class="tool-card" aria-label="Create a generated DynDNS hostname">
                <label>Router username
                  <input class="form-control" name="username" placeholder="optional" autocomplete="off" inputmode="text">
                  <span class="field-hint">Leave empty to generate one automatically.</span>
                </label>
                <button type="submit" class="btn btn-primary rounded-pill">Generate hostname</button>
              </form>
            </div>
          </section>
          {challenge_html}
          <footer class="footer">
            <div class="container footer-links">
              <a href="/docs">API docs</a>
              <a href="/redoc">ReDoc</a>
              <a href="/admin">Admin</a>
            </div>
          </footer>
        </main>
        """,
    )


def _top_nav(label: str | None = None, links: str = "") -> str:
    account_html = ""
    if label:
        account_html = f'<span class="nav-label">{html.escape(label)}</span>'
    if not links:
        account_html += '<a class="nav-button" href="/#custom-domain">Domain setup</a>'
    return f"""
    <a class="skip-link" href="#main">Skip to content</a>
    <nav class="top-nav" aria-label="Main navigation">
      <div class="container nav-inner">
        <a class="navbar-brand brand" href="/"><img src="/logo.svg" alt="" width="28" height="28">router-dyndns</a>
        <div class="nav-actions">
          {links}
          {account_html}
        </div>
      </div>
    </nav>
    """


def _custom_domain_flow(service: DdnsService, challenge: dict[str, str | None] | None, message: str | None) -> str:
    challenge_html = ""
    create_form = ""
    if challenge:
        domain = html.escape(str(challenge["domain"]))
        token = str(challenge["token"])
        claim_secret = html.escape(str(challenge.get("claim_secret") or ""))
        verification_name = service.verification_name(str(challenge["domain"]))
        claim_url = service.domain_claim_url(challenge)
        status = html.escape(message or "Add this TXT record at your DNS provider, then check when it has propagated.")
        challenge_html = f"""
        <div class="step-card">
          <span class="step-number">2</span>
          <h3>Add the TXT record</h3>
          <p class="note">{status}</p>
          {_copy_row("TXT name", verification_name)}
          {_copy_row("TXT value", token)}
          {_copy_row("Private claim link", claim_url)}
          <form method="post" action="/verify-domain" class="inline-form" aria-label="Check DNS TXT verification">
            <input type="hidden" name="domain" value="{domain}">
            <input type="hidden" name="claim_secret" value="{claim_secret}">
            <button type="submit" class="btn btn-primary rounded-pill">Check DNS record</button>
          </form>
        </div>
        """
        if challenge.get("verified_at"):
            create_form = f"""
            <div class="step-card">
              <span class="step-number">3</span>
              <h3>Create router hostname</h3>
              <form method="post" action="/accounts" class="stack-form" aria-label="Create custom-domain router credentials">
                <input type="hidden" name="mode" value="custom">
                <input type="hidden" name="claim_secret" value="{claim_secret}">
                <label>Verified hostname
                  <input class="form-control" name="hostname" placeholder="home.example.com" autocomplete="off" autocapitalize="none" spellcheck="false" required>
                </label>
                <label>Router username
                  <input class="form-control" name="username" placeholder="optional" autocomplete="off">
                  <span class="field-hint">Leave empty to generate one automatically.</span>
                </label>
                <button type="submit" class="btn btn-primary rounded-pill">Create credentials</button>
              </form>
            </div>
            """
        else:
            create_form = """
            <div class="step-card muted-card">
              <span class="step-number">3</span>
              <h3>Create router hostname</h3>
              <p class="note">This unlocks after the TXT record is visible in public DNS.</p>
            </div>
            """

    return f"""
    <section class="section section-dark" id="custom-domain">
      <div class="container">
        <div class="section-heading">
          <div>
            <p class="eyebrow">Custom domain</p>
            <h2>Verify DNS ownership</h2>
            <p class="section-copy">We only issue router credentials after the DNS record proves you control the domain.</p>
          </div>
        </div>
        <div class="step-grid">
          <div class="step-card">
            <span class="step-number">1</span>
            <h3>Enter domain</h3>
            <form method="post" action="/request-domain" class="stack-form" aria-label="Request a custom domain TXT challenge">
              <label>Domain
                <input class="form-control" name="domain" placeholder="example.com" autocomplete="off" autocapitalize="none" spellcheck="false" required>
              </label>
              <button type="submit" class="btn btn-primary rounded-pill">Create TXT challenge</button>
            </form>
          </div>
          {challenge_html}
          {create_form}
        </div>
      </div>
    </section>
    """


def _credentials_panel(service: DdnsService, created_account: dict[str, str] | None) -> str:
    if not created_account:
        return ""
    hostname = created_account["hostname"]
    username = created_account["username"]
    password = created_account["password"]
    update_url = service.fritz_update_url(created_account)
    management_url = service.magic_management_url(created_account)
    return f"""
    <section class="section success-section">
      <div class="container">
        <p class="eyebrow">Credentials generated</p>
        <h2>{html.escape(hostname)}</h2>
        <p class="section-copy">Save this now. The password and management link are only shown on this screen.</p>
        <div class="copy-list">
          {_copy_row("Update-URL:", update_url)}
          {_copy_row("Domainnamen:", hostname)}
          {_copy_row("Benutzername:", username)}
          {_copy_row("Kennwort:", password)}
          {_copy_row("Private status page:", management_url)}
        </div>
      </div>
    </section>
    """


def _created_account_panel(service: DdnsService, created_account: dict[str, str] | None) -> str:
    return _credentials_panel(service, created_account)


def _admin_secret_panel(title: str, rows: list[str]) -> str:
    return f"""
    <section class="section success-section">
      <div class="container">
        <p class="eyebrow">Admin action</p>
        <h2>{html.escape(title)}</h2>
        <p class="section-copy">Copy this now. Secret values are only shown in this response.</p>
        <div class="copy-list">
          {"".join(rows)}
        </div>
      </div>
    </section>
    """


def _copy_row(label: str, value: str) -> str:
    safe_label = html.escape(label)
    safe_value = html.escape(value)
    return f"""
    <div class="copy-row">
      <span>{safe_label}</span>
      <code>{safe_value}</code>
      <button type="button" class="btn btn-sm btn-light copy-button" data-copy="{safe_value}" aria-label="Copy {safe_label}">Copy</button>
    </div>
    """


def _message_band(message: str | None) -> str:
    if not message:
        return ""
    return f"""
    <section class="message-band">
      <div class="container"><p>{html.escape(message)}</p></div>
    </section>
    """


def _render_management_page(service: DdnsService, settings: DdnsSettings, management_slug: str, account: dict[str, str | int | None]) -> str:
    account_for_url = {
        "hostname": str(account["hostname"]),
        "username": str(account["username"]),
        "password": "",
        "update_slug": str(account["update_slug"]),
        "management_slug": management_slug,
    }
    update_url = service.fritz_update_url(account_for_url)
    hostname = html.escape(str(account["hostname"]))
    username = html.escape(str(account["username"]))
    ipv4 = html.escape(str(account.get("ipv4") or "-"))
    ipv6 = html.escape(str(account.get("ipv6") or "-"))
    updated = html.escape(str(account.get("updated_at") or "Never"))
    history_rows = "\n".join(_user_event_row(event) for event in service.store.list_update_events_for_hostname(str(account["hostname"]), 20)) or """
      <tr><td colspan="5" class="empty">No router updates yet.</td></tr>
    """
    return _page(
        "DynDNS management",
        f"""
        <main id="main">
          {_top_nav()}
          <section class="hero-band compact">
            <div class="container hero-inner">
              <p class="eyebrow">Magic management</p>
              <h1>{hostname}</h1>
              <p class="lead">Anyone with this link can manage or delete this hostname. Keep it private.</p>
              <a class="btn btn-outline-primary rounded-pill" href="/">Back home</a>
            </div>
          </section>
          <section class="section">
            <div class="container tool-grid">
              <div>
                <p class="eyebrow">Router settings</p>
                <h2>FRITZ!Box fields</h2>
                <p class="section-copy">Use these values in the FRITZ!Box custom DynDNS provider fields.</p>
              </div>
              <div class="copy-list">
                {_copy_row("Update-URL:", update_url)}
                {_copy_row("Domainnamen:", hostname)}
                {_copy_row("Benutzername:", username)}
                {_copy_row("Kennwort:", "unchanged; only shown when generated")}
              </div>
            </div>
          </section>
          <section class="section">
            <div class="container split-row">
              <div>
                <p class="eyebrow">Current address</p>
                <h2>Status</h2>
              </div>
              <table class="table status-table">
                <tbody>
                  <tr><th>IPv4</th><td>{ipv4}</td></tr>
                  <tr><th>IPv6</th><td>{ipv6}</td></tr>
                  <tr><th>Updated</th><td>{updated}</td></tr>
                </tbody>
              </table>
            </div>
          </section>
          <section class="section">
            <div class="container">
              <div class="section-heading">
                <div>
                  <p class="eyebrow">History</p>
                  <h2>Router updates</h2>
                  <p class="section-copy">Recent IP changes and failed DNS publishes for this hostname.</p>
                </div>
              </div>
              <div class="table-wrap">
                <table class="table">
                  <thead><tr><th>Time</th><th>Status</th><th>IPv4</th><th>IPv6</th><th>Detail</th></tr></thead>
                  <tbody>{history_rows}</tbody>
                </table>
              </div>
            </div>
          </section>
          <section class="section danger-section">
            <div class="container split-row">
              <div>
                <p class="eyebrow">Danger zone</p>
                <h2>Delete hostname</h2>
                <p class="section-copy">This removes the hostname and DNS records. The router update URL will stop working.</p>
              </div>
              <form method="post" action="/m/{html.escape(management_slug)}/delete">
                <button class="btn btn-outline-danger rounded-pill danger-button" type="submit">Delete hostname</button>
              </form>
            </div>
          </section>
        </main>
        """,
    )


def _render_admin_page(
    service: DdnsService,
    settings: DdnsSettings,
    accounts: list[dict[str, str | int | None]],
    domain_challenges: list[dict[str, str | None]],
    cleanup_runs: list[dict[str, str | int]],
    update_events: list[dict[str, str | None]],
    created_account: dict[str, str] | None,
    notice_html: str | None,
) -> str:
    csrf = html.escape(admin_csrf_token(settings))
    rows = "\n".join(_account_row(account, csrf=csrf) for account in accounts) or """
      <tr><td colspan="7" class="empty">No hostnames yet.</td></tr>
    """
    domain_rows = "\n".join(_domain_claim_row(challenge) for challenge in domain_challenges) or """
      <tr><td colspan="4" class="empty">No domain claims yet.</td></tr>
    """
    cleanup_rows = "\n".join(_cleanup_row(run) for run in cleanup_runs) or """
      <tr><td colspan="3" class="empty">No cleanup runs yet.</td></tr>
    """
    event_rows = "\n".join(_event_row(event) for event in update_events) or """
      <tr><td colspan="6" class="empty">No update events yet.</td></tr>
    """
    suffix_help = (
        f"Short names are expanded under {html.escape(settings.hostname_suffix)}."
        if settings.hostname_suffix
        else "Use a full hostname, for example home.example.net."
    )
    return _page(
        "DynDNS Admin",
        f"""
        <main id="main">
          {_top_nav("Operator console", '<a href="/records">Records</a><a href="/events">Events</a>')}
          <section class="section admin-heading">
            <div class="container">
              <p class="eyebrow">DynDNS aktiv</p>
              <h1>Router credentials</h1>
              <p class="lead">Create, inspect, and retire router update credentials.</p>
            </div>
          </section>

          {_created_account_panel(service, created_account)}
          {notice_html or ""}

          <section class="section">
            <div class="container tool-grid">
              <div>
                <p class="eyebrow">Service health</p>
                <h2>Scheduled cleanup</h2>
                <p class="section-copy">Cleanup runs every {html.escape(str(settings.cleanup_interval_seconds))} seconds. It removes unverified domain claims after {html.escape(str(settings.cleanup_challenge_hours))} hours and never-used generated hostnames after {html.escape(str(settings.cleanup_unused_account_hours))} hours.</p>
              </div>
              <form method="post" action="/admin/cleanup" class="tool-card" aria-label="Run cleanup now">
                <input type="hidden" name="csrf" value="{csrf}">
                <button type="submit" class="btn btn-primary rounded-pill">Run cleanup now</button>
              </form>
            </div>
          </section>

          <section class="section">
            <div class="container tool-grid">
              <div>
                <p class="eyebrow">Generate credentials</p>
                <h2>Router credentials</h2>
                <p class="section-copy">Generated credentials produce the FRITZ!Box fields: Update-URL, Domainnamen, Benutzername, Kennwort.</p>
                <p class="note">{suffix_help}</p>
              </div>
              <form method="post" action="/admin/accounts" class="tool-card" aria-label="Create router credentials">
                <input type="hidden" name="csrf" value="{csrf}">
                <label>Domainnamen
                  <input class="form-control" name="hostname" placeholder="home.example.net" autocomplete="off" autocapitalize="none" spellcheck="false" required>
                </label>
                <label>Benutzername
                  <input class="form-control" name="username" placeholder="auto-generated" autocomplete="off">
                  <span class="field-hint">Leave empty to generate one from the hostname.</span>
                </label>
                <button type="submit" class="btn btn-primary rounded-pill">Generate credentials</button>
              </form>
            </div>
          </section>

          <section class="section">
            <div class="container">
              <div class="section-heading">
                <div>
                  <p class="eyebrow">Hostnames</p>
                  <h2>Active credentials</h2>
                </div>
              </div>
              <div class="table-wrap">
                <table class="table">
                  <thead>
                    <tr><th>Domain</th><th>User</th><th>IPv4</th><th>IPv6</th><th>Updated</th><th>Links</th><th></th></tr>
                  </thead>
                  <tbody>{rows}</tbody>
                </table>
              </div>
            </div>
          </section>

          <section class="section">
            <div class="container">
              <div class="section-heading">
                <div>
                  <p class="eyebrow">Domain claims</p>
                  <h2>Verification lifecycle</h2>
                </div>
              </div>
              <div class="table-wrap">
                <table class="table">
                  <thead><tr><th>Domain</th><th>Status</th><th>Created</th><th>Verified</th></tr></thead>
                  <tbody>{domain_rows}</tbody>
                </table>
              </div>
            </div>
          </section>

          <section class="section">
            <div class="container">
              <div class="section-heading">
                <div>
                  <p class="eyebrow">Cleanup</p>
                  <h2>Recent runs</h2>
                </div>
              </div>
              <div class="table-wrap">
                <table class="table">
                  <thead><tr><th>Time</th><th>Domain claims removed</th><th>Unused hostnames removed</th></tr></thead>
                  <tbody>{cleanup_rows}</tbody>
                </table>
              </div>
            </div>
          </section>

          <section class="section">
            <div class="container">
              <div class="section-heading">
                <div>
                  <p class="eyebrow">Updates</p>
                  <h2>Recent events</h2>
                </div>
              </div>
              <div class="table-wrap">
                <table class="table">
                  <thead><tr><th>Time</th><th>Domain</th><th>Status</th><th>IPv4</th><th>IPv6</th><th>Detail</th></tr></thead>
                  <tbody>{event_rows}</tbody>
                </table>
              </div>
            </div>
          </section>
        </main>
        """,
    )


def _account_row(account: dict[str, str | int | None], csrf: str = "") -> str:
    hostname = html.escape(str(account["hostname"]))
    username = html.escape(str(account["username"]))
    ipv4 = html.escape(str(account.get("ipv4") or "-"))
    ipv6 = html.escape(str(account.get("ipv6") or "-"))
    updated = html.escape(str(account.get("updated_at") or "Never"))
    return f"""
      <tr>
        <td>{hostname}</td><td>{username}</td><td>{ipv4}</td><td>{ipv6}</td><td>{updated}</td>
        <td>
          <form method="post" action="/admin/accounts/rotate" class="table-actions">
            <input type="hidden" name="csrf" value="{html.escape(csrf)}">
            <input type="hidden" name="hostname" value="{hostname}">
            <button name="action" value="update" class="btn btn-sm btn-light small-button" title="Rotate update URL" aria-label="Rotate update URL for {hostname}">Update URL</button>
            <button name="action" value="management" class="btn btn-sm btn-light small-button" title="Rotate management link" aria-label="Rotate management link for {hostname}">Manage link</button>
            <button name="action" value="password" class="btn btn-sm btn-light small-button" title="Rotate router password" aria-label="Rotate router password for {hostname}">Password</button>
          </form>
        </td>
        <td>
          <form method="post" action="/admin/accounts/delete">
            <input type="hidden" name="csrf" value="{html.escape(csrf)}">
            <input type="hidden" name="hostname" value="{hostname}">
            <button class="btn btn-sm btn-light icon-button" title="Delete hostname" aria-label="Delete {hostname}">x</button>
          </form>
        </td>
      </tr>
    """


def _domain_claim_row(challenge: dict[str, str | None]) -> str:
    domain = html.escape(str(challenge["domain"]))
    created = html.escape(str(challenge.get("created_at") or "-"))
    verified = html.escape(str(challenge.get("verified_at") or "-"))
    status = "Verified" if challenge.get("verified_at") else "Pending"
    return f"<tr><td>{domain}</td><td>{status}</td><td>{created}</td><td>{verified}</td></tr>"


def _cleanup_row(run: dict[str, str | int]) -> str:
    created = html.escape(str(run.get("created_at") or "-"))
    domains = html.escape(str(run.get("domain_challenges_deleted") or 0))
    accounts = html.escape(str(run.get("unused_accounts_deleted") or 0))
    return f"<tr><td>{created}</td><td>{domains}</td><td>{accounts}</td></tr>"


def _event_row(event: dict[str, str | None]) -> str:
    created = html.escape(str(event.get("created_at") or "-"))
    hostname = html.escape(str(event.get("hostname") or "-"))
    status = html.escape(str(event.get("status") or "-"))
    ipv4 = html.escape(str(event.get("ipv4") or "-"))
    ipv6 = html.escape(str(event.get("ipv6") or "-"))
    detail = html.escape(str(event.get("detail") or "-"))
    return f"<tr><td>{created}</td><td>{hostname}</td><td>{status}</td><td>{ipv4}</td><td>{ipv6}</td><td>{detail}</td></tr>"


def _user_event_row(event: dict[str, str | None]) -> str:
    created = html.escape(str(event.get("created_at") or "-"))
    status = html.escape(str(event.get("status") or "-"))
    ipv4 = html.escape(str(event.get("ipv4") or "-"))
    ipv6 = html.escape(str(event.get("ipv6") or "-"))
    detail = html.escape(str(event.get("detail") or "-"))
    return f"<tr><td>{created}</td><td>{status}</td><td>{ipv4}</td><td>{ipv6}</td><td>{detail}</td></tr>"


def _page(title: str, body: str) -> str:
    return f"""
    <!doctype html>
    <html lang="en">
      <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title>{html.escape(title)}</title>
        <link rel="icon" href="/favicon.ico" sizes="any">
        <link rel="icon" href="/logo.svg" type="image/svg+xml">
        <link rel="apple-touch-icon" href="/logo.png">
        <script src="/app.js" defer></script>
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.8/dist/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-sRIl4kxILFvY47J16cr9ZwB07vP4J8+LH7qKQnuqkuIAvNWLzeN8tE5YBujZqJLB" crossorigin="anonymous">
        <style>
          :root {{
            --bs-primary: #0071e3;
            --bs-primary-rgb: 0, 113, 227;
            --bs-link-color: #0071e3;
            --bs-link-hover-color: #005bb8;
            --rp-bg: #f5f5f7;
            --rp-surface: #ffffff;
            --rp-surface-alt: #fafafc;
            --rp-ink: #1d1d1f;
            --rp-muted: #6e6e73;
            --rp-line: rgba(0, 0, 0, 0.1);
            --rp-soft-line: rgba(0, 0, 0, 0.06);
            --rp-dark: #161617;
            --rp-dark-card: #242426;
            --rp-danger: #b42318;
            --rp-nav-bg: rgba(245, 245, 247, 0.86);
          }}
          [data-bs-theme="dark"] {{
            --bs-body-bg: #0f1012;
            --bs-body-color: #f5f5f7;
            --bs-secondary-color: #a1a1aa;
            --bs-border-color: rgba(255, 255, 255, 0.16);
            --bs-tertiary-bg: #1c1d20;
            --rp-bg: #0f1012;
            --rp-surface: #16171a;
            --rp-surface-alt: #1c1d20;
            --rp-ink: #f5f5f7;
            --rp-muted: #a1a1aa;
            --rp-line: rgba(255, 255, 255, 0.16);
            --rp-soft-line: rgba(255, 255, 255, 0.1);
            --rp-dark: #050506;
            --rp-dark-card: #16171a;
            --rp-danger: #ff8a80;
            --rp-nav-bg: rgba(15, 16, 18, 0.82);
          }}
          * {{ box-sizing: border-box; }}
          html {{ scroll-behavior: smooth; }}
          body {{
            min-height: 100vh;
            background: var(--rp-bg);
            color: var(--rp-ink);
            font: 400 16px/1.45 -apple-system, BlinkMacSystemFont, "SF Pro Text", "Segoe UI", system-ui, sans-serif;
          }}
          .container {{ width: min(1040px, calc(100% - 40px)); margin: 0 auto; }}
          .skip-link {{ position: fixed; left: 16px; top: 10px; z-index: 40; transform: translateY(-140%); padding: 10px 14px; border-radius: 999px; background: var(--rp-ink); color: var(--rp-bg); text-decoration: none; font-size: 14px; transition: transform .16s ease; }}
          .skip-link:focus {{ transform: translateY(0); }}
          .top-nav {{ position: sticky; top: 0; z-index: 20; min-height: 52px; display: flex; align-items: center; background: var(--rp-nav-bg); border-bottom: 1px solid var(--rp-soft-line); backdrop-filter: saturate(180%) blur(20px); }}
          .nav-inner {{ min-height: 52px; display: flex; align-items: center; justify-content: space-between; gap: 18px; }}
          .brand {{ display: inline-flex; align-items: center; gap: 9px; color: var(--rp-ink); font-size: 15px; font-weight: 650; letter-spacing: -0.01em; text-decoration: none; white-space: nowrap; }}
          .brand:hover {{ color: var(--rp-ink); }}
          .brand img {{ width: 28px; height: 28px; display: block; }}
          .nav-actions {{ min-width: 0; display: flex; align-items: center; justify-content: flex-end; gap: 14px; }}
          .nav-actions a:not(.nav-button) {{ color: var(--rp-muted); font-size: 13px; text-decoration: none; white-space: nowrap; }}
          .nav-actions a:not(.nav-button):hover {{ color: var(--rp-ink); }}
          .nav-label {{ min-width: 0; max-width: 38vw; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; color: var(--rp-muted); font-size: 13px; }}
          .nav-button {{ min-height: 34px; padding: 0 14px; display: inline-flex; align-items: center; justify-content: center; border: 1px solid var(--rp-line); border-radius: 999px; background: var(--rp-surface-alt); color: var(--rp-ink); font: inherit; font-size: 13px; font-weight: 500; text-decoration: none; cursor: pointer; }}
          .nav-button:hover {{ background: var(--bs-tertiary-bg); color: var(--rp-ink); }}
          .hero-band {{ min-height: calc(70vh - 52px); display: grid; align-items: center; background: var(--rp-bg); text-align: center; padding: 80px 0 72px; }}
          .hero-band.compact {{ min-height: 360px; }}
          .hero-inner {{ display: grid; justify-items: center; gap: 18px; }}
          .section {{ padding: 68px 0; background: var(--rp-surface); }}
          .section + .section {{ border-top: 1px solid var(--rp-soft-line); }}
          .section-dark {{ background: var(--rp-dark); color: #f5f5f7; border-top: 0; }}
          .success-section {{ background: var(--rp-bg); }}
          .danger-section {{ background: var(--rp-surface); border-top: 1px solid var(--rp-soft-line); }}
          .message-band {{ background: var(--bs-warning-bg-subtle); color: var(--rp-ink); padding: 18px 0; border-block: 1px solid var(--bs-warning-border-subtle); }}
          .split-row, .section-heading {{ display: flex; align-items: center; justify-content: space-between; gap: 24px; }}
          .page-heading, .admin-heading .container {{ max-width: 760px; }}
          .button-row {{ display: flex; gap: 10px; flex-wrap: wrap; }}
          h1, h2, h3, p {{ margin: 0; }}
          h1 {{ max-width: 760px; font-size: 48px; line-height: 1.08; font-weight: 650; letter-spacing: -0.02em; }}
          h2 {{ font-size: 28px; line-height: 1.16; font-weight: 600; letter-spacing: -0.015em; }}
          h3 {{ font-size: 18px; line-height: 1.25; font-weight: 600; }}
          .eyebrow {{ color: var(--bs-primary); font-size: 13px; font-weight: 600; letter-spacing: 0; }}
          .lead {{ max-width: 660px; color: var(--rp-muted); font-size: 19px; line-height: 1.47; letter-spacing: -0.01em; }}
          .section-dark .lead, .section-dark .section-copy, .section-dark .note {{ color: #cccccc; }}
          .section-copy, .intro {{ margin-top: 12px; max-width: 560px; color: var(--rp-muted); font-size: 15px; line-height: 1.5; }}
          .hero-actions {{ display: flex; gap: 12px; flex-wrap: wrap; justify-content: center; margin-top: 8px; }}
          .tool-grid {{ display: grid; grid-template-columns: minmax(0, 1fr) minmax(320px, 440px); gap: 40px; align-items: start; }}
          .tool-card, .step-card, .secondary-card {{ display: grid; gap: 16px; padding: 24px; background: var(--rp-surface); border: 1px solid var(--rp-line); border-radius: .75rem; }}
          .secondary-card {{ background: var(--rp-surface-alt); }}
          .section-dark .step-card {{ background: var(--rp-dark-card); border-color: rgba(255, 255, 255, 0.14); }}
          .section-dark .muted-card {{ opacity: .66; }}
          .step-grid {{ display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 18px; margin-top: 28px; }}
          .stack-form {{ display: grid; gap: 16px; }}
          .inline-form {{ margin-top: 14px; }}
          label {{ display: grid; gap: 8px; color: var(--rp-muted); font-size: 13px; font-weight: 500; }}
          input {{ width: 100%; min-height: 44px; border: 1px solid var(--bs-border-color); border-radius: .5rem; padding: 10px 12px; color: var(--bs-body-color); font: inherit; background: var(--bs-body-bg); outline: none; }}
          input:focus {{ border-color: var(--bs-primary); box-shadow: 0 0 0 .25rem rgba(var(--bs-primary-rgb), .16); }}
          .field-hint {{ color: var(--rp-muted); font-size: 12px; font-weight: 400; line-height: 1.35; }}
          .btn {{ min-height: 44px; display: inline-flex; align-items: center; justify-content: center; gap: 8px; font-size: 15px; font-weight: 500; transition: background-color .16s ease, border-color .16s ease, transform .16s ease; }}
          .btn:active {{ transform: scale(.97); }}
          .btn:focus-visible, a:focus-visible, input:focus-visible {{ outline: 2px solid var(--bs-primary); outline-offset: 3px; }}
          .btn-light {{ --bs-btn-bg: var(--rp-surface-alt); --bs-btn-border-color: var(--rp-line); --bs-btn-color: var(--rp-ink); --bs-btn-hover-bg: var(--bs-tertiary-bg); --bs-btn-hover-border-color: var(--rp-line); --bs-btn-hover-color: var(--rp-ink); }}
          .danger-button {{ color: var(--rp-danger); }}
          .note {{ margin-top: 10px; color: var(--rp-muted); font-size: 13px; line-height: 1.45; }}
          .copy-list {{ display: grid; gap: 10px; }}
          .copy-row {{ display: grid; grid-template-columns: 150px minmax(0, 1fr) auto; gap: 12px; align-items: center; min-height: 48px; padding: 10px 10px 10px 14px; background: var(--rp-surface); border: 1px solid var(--rp-line); border-radius: .5rem; }}
          .copy-row span {{ color: var(--rp-muted); font-size: 13px; }}
          .copy-row code {{ min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; color: var(--rp-ink); font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 13px; }}
          .copy-button {{ min-height: 32px; padding: 0 12px; border-radius: 999px; color: var(--bs-primary); font-size: 13px; }}
          .section-dark .copy-row {{ background: #1d1d1f; border-color: rgba(255, 255, 255, 0.14); }}
          .section-dark .copy-row code {{ color: #f5f5f7; }}
          .step-number {{ width: 28px; height: 28px; display: inline-flex; align-items: center; justify-content: center; background: var(--bs-primary); color: white; border-radius: 50%; font-size: 13px; }}
          .table-wrap {{ overflow-x: auto; border: 1px solid var(--rp-line); border-radius: .5rem; }}
          table {{ width: 100%; border-collapse: collapse; font-size: 14px; font-variant-numeric: tabular-nums; color: var(--rp-ink); }}
          th, td {{ border-bottom: 1px solid var(--rp-soft-line); padding: 14px 10px; text-align: left; white-space: nowrap; }}
          tr:last-child th, tr:last-child td {{ border-bottom: 0; }}
          th {{ color: var(--rp-muted); font-size: 12px; font-weight: 600; }}
          .empty {{ color: var(--rp-muted); text-align: center; padding: 28px; }}
          .icon-button {{ width: 32px; min-height: 32px; padding: 0; color: var(--rp-danger); }}
          .table-actions {{ display: flex; gap: 6px; flex-wrap: wrap; }}
          .small-button {{ min-height: 32px; padding: 0 11px; color: var(--bs-primary); font-size: 12px; }}
          .footer {{ padding: 28px 0; background: var(--rp-bg); border-top: 1px solid var(--rp-soft-line); }}
          .footer-links {{ display: flex; justify-content: center; gap: 18px; flex-wrap: wrap; }}
          .footer-links a {{ color: var(--rp-muted); font-size: 13px; text-decoration: none; }}
          .footer-links a:hover {{ color: var(--rp-ink); }}
          @media (max-width: 860px) {{
            .tool-grid, .step-grid {{ grid-template-columns: 1fr; }}
            .split-row, .section-heading {{ align-items: flex-start; flex-direction: column; }}
            .section, .hero-band {{ padding: 52px 0; }}
            .hero-band {{ min-height: auto; }}
            h1 {{ font-size: 36px; }}
            .lead {{ font-size: 17px; }}
          }}
          @media (max-width: 560px) {{
            .container {{ width: min(100% - 28px, 1040px); }}
            .nav-inner {{ gap: 10px; }}
            .nav-actions {{ gap: 8px; }}
            .nav-label {{ display: none; }}
            .brand {{ font-size: 14px; }}
            .brand img {{ width: 24px; height: 24px; }}
            .hero-actions, .button-row {{ width: 100%; flex-direction: column; }}
            .hero-actions .btn, .tool-card button, .step-card button, .danger-button {{ width: 100%; }}
            .tool-card, .step-card, .secondary-card {{ padding: 18px; }}
            .copy-row {{ grid-template-columns: 1fr; }}
            .copy-row code {{ white-space: normal; overflow-wrap: anywhere; }}
            .copy-button {{ width: 100%; }}
            .table-wrap {{ margin-inline: -4px; }}
            th, td {{ padding: 12px 9px; }}
            h1 {{ font-size: 31px; }}
            h2 {{ font-size: 25px; }}
          }}
        </style>
      </head>
      <body>{body}</body>
    </html>
    """

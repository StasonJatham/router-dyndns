from __future__ import annotations

import html
import secrets
import sqlite3
import urllib.parse
from pathlib import Path
from typing import Annotated

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request, Response
from fastapi.responses import FileResponse, HTMLResponse, PlainTextResponse, RedirectResponse
from starlette.concurrency import run_in_threadpool

from .ddns_api import create_api_router
from .ddns_dns import delete_dns_records, dns_backend_configured, publish_dns
from .ddns_models import DdnsSettings, UpdateResult
from .ddns_security import (
    admin_csrf_token,
    client_ip,
    credentials_from_basic_auth,
    is_rate_limited_path,
    normalize_email,
    require_admin_csrf,
    set_session_cookie,
    verify_session_cookie,
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
    {
        "name": "admin",
        "description": "Operator-only HTML and JSON endpoints protected by the admin password.",
    },
]

ASSET_DIR = Path(__file__).with_name("assets")


def make_app(settings: DdnsSettings | None = None) -> FastAPI:
    settings = settings or DdnsSettings.from_env()
    if not settings.admin_password and settings.shared_secret:
        settings = settings.model_copy(update={"admin_password": settings.shared_secret})
    if not settings.session_secret:
        settings = settings.model_copy(update={"session_secret": settings.admin_password or settings.shared_secret})
    if settings.require_dns_provider and not dns_backend_configured(settings):
        raise RuntimeError("DDNS_REQUIRE_DNS_PROVIDER is set but no DNS backend is configured")

    store = DdnsStore(settings.database_path)
    store.cleanup(settings.cleanup_challenge_hours)
    service = DdnsService(settings, store)
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
    )
    app.include_router(create_api_router(settings, store, service))

    @app.middleware("http")
    async def security_middleware(request: Request, call_next):
        if is_rate_limited_path(request.url.path):
            key = f"{client_ip(request, settings)}:{request.url.path}"
            allowed = await run_in_threadpool(store.allow_rate_limit, key, settings.rate_limit_per_minute)
            if not allowed:
                return PlainTextResponse("rate limit exceeded", status_code=429)

        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "same-origin"
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'unsafe-inline' 'self'; style-src 'unsafe-inline' 'self'; form-action 'self'; frame-ancestors 'none'"
        )
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

    def current_user(request: Request) -> dict[str, str | int] | None:
        user_id = verify_session_cookie(request.cookies.get("ddns_session"), settings.session_secret)
        return store.get_user(user_id) if user_id is not None else None

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
    def index(request: Request) -> str:
        user = current_user(request)
        if user:
            return _render_user_home(service, settings, user, store.list_accounts(int(user["id"])), None, None, None)
        return _render_public_home(service, settings, None, None)

    @app.get("/login", response_class=HTMLResponse)
    def login_page() -> str:
        return _render_auth_page(settings, None)

    @app.post("/magic", response_class=HTMLResponse)
    async def magic_account(request: Request) -> str:
        form = _parse_form(await request.body())
        username = _first_form_value(form, "username") or None
        account = await run_in_threadpool(service.create_managed_account, username, None)
        return _render_public_home(service, settings, account, None)

    @app.get("/m/{management_slug}", response_class=HTMLResponse)
    def manage_magic(management_slug: str) -> str:
        account = store.get_account_by_management_slug(management_slug)
        if not account or account["disabled"]:
            raise HTTPException(status_code=404, detail="not found")
        return _render_management_page(service, settings, management_slug, account)

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
                      <a class="button secondary" href="/">Home</a>
                    </div>
                  </section>
                </main>
                """,
            )
        )

    @app.post("/request-domain", response_class=HTMLResponse)
    async def request_domain(request: Request) -> str:
        user = await run_in_threadpool(current_user, request)
        if not user:
            raise HTTPException(status_code=401, detail="authentication required")
        form = _parse_form(await request.body())
        try:
            challenge = await run_in_threadpool(service.create_domain_challenge, _first_form_value(form, "domain"), int(user["id"]))
        except sqlite3.IntegrityError as exc:
            raise HTTPException(status_code=409, detail="domain is already verified") from exc
        return _render_user_home(service, settings, user, store.list_accounts(int(user["id"])), None, None, challenge)

    @app.post("/verify-domain", response_class=HTMLResponse)
    async def verify_domain(request: Request) -> str:
        user = await run_in_threadpool(current_user, request)
        if not user:
            raise HTTPException(status_code=401, detail="authentication required")
        form = _parse_form(await request.body())
        domain = normalize_domain(_first_form_value(form, "domain"))
        claim_secret = _first_form_value(form, "claim_secret")
        found, challenge = await run_in_threadpool(service.verify_domain, domain, claim_secret, int(user["id"]))
        if not found:
            return _render_user_home(
                service,
                settings,
                user,
                store.list_accounts(int(user["id"])),
                None,
                "TXT record not found yet. DNS propagation can take a few minutes.",
                challenge,
            )
        return _render_user_home(service, settings, user, store.list_accounts(int(user["id"])), None, "Domain verified. You can now create a hostname under it.", challenge)

    @app.post("/accounts", response_class=HTMLResponse)
    async def self_service_account(request: Request) -> str:
        user = await run_in_threadpool(current_user, request)
        if not user:
            raise HTTPException(status_code=401, detail="authentication required")
        form = _parse_form(await request.body())
        mode = _first_form_value(form, "mode")
        username = _first_form_value(form, "username") or None
        if mode == "managed":
            account = await run_in_threadpool(service.create_managed_account, username, int(user["id"]))
        else:
            claim_secret = _first_form_value(form, "claim_secret")
            account = await run_in_threadpool(
                service.create_custom_account,
                _first_form_value(form, "hostname"),
                claim_secret,
                username,
                int(user["id"]),
            )
        return _render_user_home(service, settings, user, store.list_accounts(int(user["id"])), account, None, None)

    @app.post("/register")
    async def register(request: Request) -> Response:
        form = _parse_form(await request.body())
        email = normalize_email(_first_form_value(form, "email"))
        password = _first_form_value(form, "password")
        invite = _first_form_value(form, "invite")
        if not email or len(password) < 12:
            return HTMLResponse(_render_auth_page(settings, "Use a valid email and a password with at least 12 characters."))
        try:
            user = await run_in_threadpool(store.create_user, email, password, invite, settings.require_invite)
        except (sqlite3.IntegrityError, ValueError):
            return HTMLResponse(
                _render_auth_page(settings, "Registration failed. Check the invite code and email address."),
                status_code=400,
            )
        response = RedirectResponse("/", status_code=303)
        set_session_cookie(response, settings, int(user["id"]))
        return response

    @app.post("/login")
    async def login(request: Request) -> Response:
        form = _parse_form(await request.body())
        user = await run_in_threadpool(store.authenticate_user, normalize_email(_first_form_value(form, "email")), _first_form_value(form, "password"))
        if not user:
            return HTMLResponse(_render_auth_page(settings, "Login failed."), status_code=401)
        response = RedirectResponse("/", status_code=303)
        set_session_cookie(response, settings, int(user["id"]))
        return response

    @app.post("/logout")
    def logout() -> Response:
        response = RedirectResponse("/", status_code=303)
        response.delete_cookie("ddns_session")
        return response

    @app.get("/admin", response_class=HTMLResponse)
    def admin(_: None = Depends(authenticate_admin)) -> str:
        return _render_admin_page(service, settings, store.list_accounts(), store.list_invites(), None)

    @app.post("/admin/accounts")
    async def admin_create_account(request: Request, _: None = Depends(authenticate_admin)) -> Response:
        form = _parse_form(await request.body())
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
        return HTMLResponse(_render_admin_page(service, settings, store.list_accounts(), store.list_invites(), account))

    @app.post("/admin/accounts/delete")
    async def admin_delete_account(request: Request, _: None = Depends(authenticate_admin)) -> Response:
        form = _parse_form(await request.body())
        require_admin_csrf(settings, _first_form_value(form, "csrf"))
        hostname = _first_form_value(form, "hostname")
        if hostname:
            try:
                service.delete_account(hostname, "admin")
            except Exception:
                return PlainTextResponse("DNS delete failed; hostname was not deleted", status_code=500)
        return RedirectResponse("/admin", status_code=303)

    @app.post("/admin/invites")
    async def create_invite(request: Request, _: None = Depends(authenticate_admin)) -> Response:
        form = _parse_form(await request.body())
        require_admin_csrf(settings, _first_form_value(form, "csrf"))
        store.create_invite()
        return RedirectResponse("/admin", status_code=303)

    @app.get("/records")
    def records(_: None = Depends(authenticate_admin)) -> list[dict[str, str | None]]:
        return store.list_records()

    @app.get("/events")
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


def _parse_form(body: bytes) -> dict[str, list[str]]:
    return urllib.parse.parse_qs(body.decode("utf-8"), keep_blank_values=True)


def _first_form_value(form: dict[str, list[str]], key: str) -> str:
    return form.get(key, [""])[0].strip()


def _render_magic_page(
    service: DdnsService,
    settings: DdnsSettings,
    created_account: dict[str, str] | None,
    message: str | None,
    challenge: dict[str, str | None] | None = None,
) -> str:
    return _render_public_home(service, settings, created_account, message, challenge)


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
    return _page(
        "router-dyndns",
        f"""
        <main>
          {_top_nav()}
          <section class="hero-band">
            <div class="container hero-inner">
              <p class="eyebrow">FRITZ!Box compatible</p>
              <h1>DynDNS without the account ceremony.</h1>
              <p class="lead">Create a secure update endpoint under {suffix}. Provider hostnames are anonymous; custom domains require DNS proof.</p>
              <div class="hero-actions">
                <a class="button" href="#create">Create hostname</a>
                <a class="button secondary" href="/login">Use custom domain</a>
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
              <form method="post" action="/magic" class="tool-card">
                <label>Username
                  <input name="username" placeholder="optional">
                </label>
                <button type="submit">Create hostname</button>
              </form>
            </div>
          </section>
          <section class="section section-dark">
            <div class="container split-row">
              <div>
                <p class="eyebrow">Custom domains</p>
                <h2>Use your own domain after TXT verification.</h2>
                <p class="section-copy">Enter your domain, add the TXT record we show you, then press the check button. We verify public DNS before credentials are issued.</p>
              </div>
              <a class="button secondary-on-dark" href="/login">Set up domain</a>
            </div>
          </section>
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


def _render_user_home(
    service: DdnsService,
    settings: DdnsSettings,
    user: dict[str, str | int],
    accounts: list[dict[str, str | int | None]],
    created_account: dict[str, str] | None,
    message: str | None,
    challenge: dict[str, str | None] | None = None,
) -> str:
    created_html = _credentials_panel(service, created_account)
    message_html = _message_band(message) if message and not challenge else ""
    account_rows = "\n".join(_account_row(account, show_owner=False) for account in accounts) or """
      <tr><td colspan="6" class="empty">No hostnames yet.</td></tr>
    """
    return _page(
        "router-dyndns dashboard",
        f"""
        <main>
          {_top_nav(str(user["email"]), True)}
          <section class="section">
            <div class="container page-heading">
              <p class="eyebrow">Dashboard</p>
              <h1>Your router hostnames</h1>
              <p class="lead">Create provider hostnames immediately, or add a domain and verify it with a DNS TXT record.</p>
            </div>
          </section>
          {message_html}
          {created_html}
          <section class="section">
            <div class="container tool-grid">
              <div>
                <p class="eyebrow">Provider hostname</p>
                <h2>Create a random hostname</h2>
                <p class="section-copy">Best for simple FRITZ!Box setups. The hostname and update link are generated for you.</p>
              </div>
              <form method="post" action="/accounts" class="tool-card">
                <input type="hidden" name="mode" value="managed">
                <label>Username
                  <input name="username" placeholder="optional">
                </label>
                <button type="submit">Create hostname</button>
              </form>
            </div>
          </section>
          {_custom_domain_flow(service, challenge, message)}
          <section class="section">
            <div class="container">
              <div class="section-heading">
                <div>
                  <p class="eyebrow">Inventory</p>
                  <h2>Hostnames</h2>
                </div>
              </div>
              <div class="table-wrap">
                <table>
                  <thead><tr><th>Domain</th><th>User</th><th>IPv4</th><th>IPv6</th><th>Updated</th><th></th></tr></thead>
                  <tbody>{account_rows}</tbody>
                </table>
              </div>
            </div>
          </section>
        </main>
        """,
    )


def _render_auth_page(settings: DdnsSettings, message: str | None) -> str:
    invite_field = """
      <label>Invite code
        <input name="invite" autocomplete="off" required>
      </label>
    """ if settings.require_invite else ""
    return _page(
        "Sign in",
        f"""
        <main>
          {_top_nav()}
          <section class="hero-band compact">
            <div class="container hero-inner">
              <p class="eyebrow">Custom domains</p>
              <h1>Set up a verified domain.</h1>
              <p class="lead">Create a small private workspace, enter your domain, add the TXT record we generate, then check public DNS.</p>
            </div>
          </section>
          {_message_band(message) if message else ""}
          <section class="section">
            <div class="container auth-grid">
              <div class="tool-card">
                <h2>Login</h2>
                <form method="post" action="/login" class="stack-form">
                  <label>Email<input name="email" type="email" autocomplete="email" required></label>
                  <label>Password<input name="password" type="password" autocomplete="current-password" required></label>
                  <button type="submit">Login</button>
                </form>
              </div>
              <div class="tool-card secondary-card">
                <h2>Register</h2>
                <form method="post" action="/register" class="stack-form">
                  <label>Email<input name="email" type="email" autocomplete="email" required></label>
                  <label>Password<input name="password" type="password" autocomplete="new-password" minlength="12" required></label>
                  {invite_field}
                  <button type="submit">Create account</button>
                </form>
              </div>
            </div>
          </section>
        </main>
        """,
    )


def _render_public_page(
    service: DdnsService,
    settings: DdnsSettings,
    user: dict[str, str | int] | None,
    accounts: list[dict[str, str | int | None]],
    challenge: dict[str, str | None] | None,
    message: str | None,
    created_account: dict[str, str] | None = None,
) -> str:
    if user:
        return _render_user_home(service, settings, user, accounts, created_account, message, challenge)
    return _render_auth_page(settings, message)


def _top_nav(label: str | None = None, show_logout: bool = False, links: str = "") -> str:
    account_html = ""
    if label:
        account_html = f'<span class="nav-label">{html.escape(label)}</span>'
    if show_logout:
        account_html += '<form method="post" action="/logout"><button class="nav-button" type="submit">Logout</button></form>'
    elif not links:
        account_html += '<a class="nav-button" href="/login">Domain setup</a>'
    return f"""
    <nav class="top-nav">
      <div class="container nav-inner">
        <a class="brand" href="/"><img src="/logo.svg" alt="" width="28" height="28">router-dyndns</a>
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
        status = html.escape(message or "Add this TXT record at your DNS provider, then press the check button.")
        challenge_html = f"""
        <div class="step-card">
          <span class="step-number">2</span>
          <h3>Add the TXT record</h3>
          <p class="note">{status}</p>
          {_copy_row("TXT name", verification_name)}
          {_copy_row("TXT value", token)}
          <form method="post" action="/verify-domain" class="inline-form">
            <input type="hidden" name="domain" value="{domain}">
            <input type="hidden" name="claim_secret" value="{claim_secret}">
            <button type="submit">I added it, check DNS</button>
          </form>
        </div>
        """
        if challenge.get("verified_at"):
            create_form = f"""
            <div class="step-card">
              <span class="step-number">3</span>
              <h3>Create router hostname</h3>
              <form method="post" action="/accounts" class="stack-form">
                <input type="hidden" name="mode" value="custom">
                <input type="hidden" name="claim_secret" value="{claim_secret}">
                <label>Verified hostname
                  <input name="hostname" placeholder="home.example.com" required>
                </label>
                <label>Username
                  <input name="username" placeholder="optional">
                </label>
                <button type="submit">Create credentials</button>
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
    <section class="section section-dark">
      <div class="container">
        <div class="section-heading">
          <div>
            <p class="eyebrow">Custom domain</p>
            <h2>Enter domain, add TXT, check DNS.</h2>
            <p class="section-copy">We only issue router credentials after the DNS record proves you control the domain.</p>
          </div>
        </div>
        <div class="step-grid">
          <div class="step-card">
            <span class="step-number">1</span>
            <h3>Enter domain</h3>
            <form method="post" action="/request-domain" class="stack-form">
              <label>Domain
                <input name="domain" placeholder="example.com" required>
              </label>
              <button type="submit">Generate TXT record</button>
            </form>
          </div>
          {challenge_html}
          {create_form}
        </div>
      </div>
    </section>
    """


def _challenge_panel(service: DdnsService, challenge: dict[str, str | None] | None, message: str | None) -> str:
    return _custom_domain_flow(service, challenge, message)


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
        <p class="eyebrow">Account generated</p>
        <h2>{html.escape(hostname)}</h2>
        <p class="section-copy">Save this now. The password and management link are only shown on this screen.</p>
        <div class="copy-list">
          {_copy_row("Update-URL:", update_url)}
          {_copy_row("Domainnamen:", hostname)}
          {_copy_row("Benutzername:", username)}
          {_copy_row("Kennwort:", password)}
          {_copy_row("Magic management link:", management_url)}
        </div>
      </div>
    </section>
    """


def _created_account_panel(service: DdnsService, created_account: dict[str, str] | None) -> str:
    return _credentials_panel(service, created_account)


def _copy_row(label: str, value: str) -> str:
    safe_label = html.escape(label)
    safe_value = html.escape(value)
    return f"""
    <div class="copy-row">
      <span>{safe_label}</span>
      <code>{safe_value}</code>
      <button type="button" class="copy-button" data-copy="{safe_value}">Copy</button>
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
    return _page(
        "DynDNS management",
        f"""
        <main>
          {_top_nav()}
          <section class="hero-band compact">
            <div class="container hero-inner">
              <p class="eyebrow">Magic management</p>
              <h1>{hostname}</h1>
              <p class="lead">Anyone with this link can manage or delete this hostname. Keep it private.</p>
              <a class="button secondary" href="/">Home</a>
            </div>
          </section>
          <section class="section">
            <div class="container tool-grid">
              <div>
                <p class="eyebrow">Router settings</p>
                <h2>FRITZ!Box fields</h2>
                <p class="section-copy">Use these values in the custom DynDNS provider fields.</p>
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
              <table class="status-table">
                <tbody>
                  <tr><th>IPv4</th><td>{ipv4}</td></tr>
                  <tr><th>IPv6</th><td>{ipv6}</td></tr>
                  <tr><th>Updated</th><td>{updated}</td></tr>
                </tbody>
              </table>
            </div>
          </section>
          <section class="section danger-section">
            <div class="container split-row">
              <div>
                <p class="eyebrow">Danger zone</p>
                <h2>Delete hostname</h2>
                <p class="section-copy">This removes the account and DNS records. The router update URL will stop working.</p>
              </div>
              <form method="post" action="/m/{html.escape(management_slug)}/delete">
                <button class="danger-button" type="submit">Delete hostname</button>
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
    invites: list[dict[str, str | None]],
    created_account: dict[str, str] | None,
) -> str:
    csrf = html.escape(admin_csrf_token(settings))
    rows = "\n".join(_account_row(account, show_owner=True, csrf=csrf) for account in accounts) or """
      <tr><td colspan="7" class="empty">No accounts yet.</td></tr>
    """
    invite_rows = "\n".join(_invite_row(invite) for invite in invites) or """
      <tr><td colspan="3" class="empty">No invites yet.</td></tr>
    """
    suffix_help = (
        f"Short names are expanded under {html.escape(settings.hostname_suffix)}."
        if settings.hostname_suffix
        else "Use a full hostname, for example home.example.net."
    )
    return _page(
        "DynDNS Admin",
        f"""
        <main>
          {_top_nav("Operator console", False, '<a href="/records">Records</a><a href="/events">Events</a>')}
          <section class="section admin-heading">
            <div class="container">
              <p class="eyebrow">DynDNS aktiv</p>
              <h1>FRITZ!Box accounts</h1>
              <p class="lead">Create, inspect, and retire router update credentials.</p>
            </div>
          </section>

          {_created_account_panel(service, created_account)}

          <section class="section">
            <div class="container tool-grid">
              <div>
                <p class="eyebrow">Generate account</p>
                <h2>Router credentials</h2>
                <p class="section-copy">Generated accounts produce the FRITZ!Box fields: Update-URL, Domainnamen, Benutzername, Kennwort.</p>
                <p class="note">{suffix_help}</p>
              </div>
              <form method="post" action="/admin/accounts" class="tool-card">
                <input type="hidden" name="csrf" value="{csrf}">
                <label>Domainnamen
                  <input name="hostname" placeholder="home.example.net" required>
                </label>
                <label>Benutzername
                  <input name="username" placeholder="auto-generated">
                </label>
                <button type="submit">Generate</button>
              </form>
            </div>
          </section>

          <section class="section">
            <div class="container">
              <div class="section-heading">
                <div>
                  <p class="eyebrow">Invites</p>
                  <h2>Registration codes</h2>
                </div>
                <form method="post" action="/admin/invites">
                  <input type="hidden" name="csrf" value="{csrf}">
                  <button type="submit">Create invite</button>
                </form>
              </div>
              <div class="table-wrap">
                <table>
                  <thead><tr><th>Code</th><th>Created</th><th>Used</th></tr></thead>
                  <tbody>{invite_rows}</tbody>
                </table>
              </div>
            </div>
          </section>

          <section class="section">
            <div class="container">
              <div class="section-heading">
                <div>
                  <p class="eyebrow">Accounts</p>
                  <h2>Active credentials</h2>
                </div>
              </div>
              <div class="table-wrap">
                <table>
                  <thead>
                    <tr><th>Domain</th><th>User</th><th>Owner</th><th>IPv4</th><th>IPv6</th><th>Updated</th><th></th></tr>
                  </thead>
                  <tbody>{rows}</tbody>
                </table>
              </div>
            </div>
          </section>
        </main>
        """,
    )


def _account_row(account: dict[str, str | int | None], show_owner: bool, csrf: str = "") -> str:
    hostname = html.escape(str(account["hostname"]))
    username = html.escape(str(account["username"]))
    ipv4 = html.escape(str(account.get("ipv4") or "-"))
    ipv6 = html.escape(str(account.get("ipv6") or "-"))
    updated = html.escape(str(account.get("updated_at") or "Never"))
    owner = f"<td>{html.escape(str(account.get('owner_user_id') or '-'))}</td>" if show_owner else ""
    return f"""
      <tr>
        <td>{hostname}</td><td>{username}</td>{owner}<td>{ipv4}</td><td>{ipv6}</td><td>{updated}</td>
        <td>
          <form method="post" action="/admin/accounts/delete">
            <input type="hidden" name="csrf" value="{html.escape(csrf)}">
            <input type="hidden" name="hostname" value="{hostname}">
            <button class="icon-button" title="Delete account" aria-label="Delete account">x</button>
          </form>
        </td>
      </tr>
    """


def _invite_row(invite: dict[str, str | None]) -> str:
    code = html.escape(str(invite["code"]))
    created = html.escape(str(invite.get("created_at") or "-"))
    used = html.escape(str(invite.get("used_at") or "-"))
    return f"<tr><td><input readonly value=\"{code}\"></td><td>{created}</td><td>{used}</td></tr>"


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
        <style>
          :root {{
            color-scheme: light;
            --bg: #f5f5f7;
            --surface: #ffffff;
            --ink: #1d1d1f;
            --muted: #6e6e73;
            --line: #d2d2d7;
            --soft-line: rgba(0, 0, 0, 0.08);
            --blue: #0071e3;
            --blue-hover: #0077ed;
            --dark: #161617;
            --dark-2: #1d1d1f;
            --danger: #b42318;
          }}
          * {{ box-sizing: border-box; }}
          html {{ scroll-behavior: smooth; }}
          body {{
            margin: 0;
            min-height: 100vh;
            background: var(--bg);
            color: var(--ink);
            font: 400 16px/1.45 -apple-system, BlinkMacSystemFont, "SF Pro Text", "Segoe UI", system-ui, sans-serif;
          }}
          .container {{ width: min(1040px, calc(100% - 40px)); margin: 0 auto; }}
          .top-nav {{ position: sticky; top: 0; z-index: 20; min-height: 52px; display: flex; align-items: center; background: rgba(245, 245, 247, 0.86); border-bottom: 1px solid rgba(0, 0, 0, 0.08); backdrop-filter: saturate(180%) blur(20px); }}
          .nav-inner {{ min-height: 52px; display: flex; align-items: center; justify-content: space-between; gap: 18px; }}
          .brand {{ display: inline-flex; align-items: center; gap: 9px; color: var(--ink); font-size: 15px; font-weight: 650; letter-spacing: -0.01em; text-decoration: none; white-space: nowrap; }}
          .brand img {{ width: 28px; height: 28px; display: block; }}
          .nav-actions {{ min-width: 0; display: flex; align-items: center; justify-content: flex-end; gap: 14px; }}
          .nav-actions a:not(.nav-button) {{ color: var(--muted); font-size: 13px; text-decoration: none; white-space: nowrap; }}
          .nav-actions a:not(.nav-button):hover {{ color: var(--ink); }}
          .nav-label {{ min-width: 0; max-width: 38vw; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; color: var(--muted); font-size: 13px; }}
          .nav-button {{ min-height: 34px; padding: 0 14px; display: inline-flex; align-items: center; justify-content: center; border: 0; border-radius: 999px; background: #e8e8ed; color: var(--ink); font: inherit; font-size: 13px; font-weight: 500; text-decoration: none; cursor: pointer; }}
          .nav-button:hover {{ background: #dedee3; }}
          .hero-band {{ min-height: calc(74vh - 52px); display: grid; align-items: center; background: var(--bg); text-align: center; padding: 84px 0; }}
          .hero-band.compact {{ min-height: 420px; }}
          .hero-inner {{ display: grid; justify-items: center; gap: 18px; }}
          .section {{ padding: 72px 0; background: var(--surface); }}
          .section + .section {{ border-top: 1px solid rgba(0, 0, 0, 0.04); }}
          .section-dark {{ background: var(--dark); color: #f5f5f7; border-top: 0; }}
          .success-section {{ background: #f5f5f7; }}
          .danger-section {{ background: #fff; border-top: 1px solid var(--soft-line); }}
          .message-band {{ background: #fff8e6; color: var(--ink); padding: 18px 0; border-block: 1px solid #f0cc74; }}
          .split-row, .section-heading {{ display: flex; align-items: center; justify-content: space-between; gap: 24px; }}
          .page-heading, .admin-heading .container {{ max-width: 760px; }}
          .button-row {{ display: flex; gap: 10px; flex-wrap: wrap; }}
          h1, h2, h3, p {{ margin: 0; }}
          h1 {{ max-width: 760px; font-size: 48px; line-height: 1.08; font-weight: 650; letter-spacing: -0.02em; }}
          h2 {{ font-size: 28px; line-height: 1.16; font-weight: 600; letter-spacing: -0.015em; }}
          h3 {{ font-size: 18px; line-height: 1.25; font-weight: 600; }}
          .eyebrow {{ color: var(--blue); font-size: 13px; font-weight: 600; letter-spacing: 0; }}
          .lead {{ max-width: 660px; color: var(--muted); font-size: 19px; line-height: 1.47; letter-spacing: -0.01em; }}
          .section-dark .lead, .section-dark .section-copy, .section-dark .note {{ color: #cccccc; }}
          .section-copy, .intro {{ margin-top: 12px; max-width: 560px; color: var(--muted); font-size: 15px; line-height: 1.5; }}
          .hero-actions {{ display: flex; gap: 12px; flex-wrap: wrap; justify-content: center; margin-top: 8px; }}
          .tool-grid {{ display: grid; grid-template-columns: minmax(0, 1fr) minmax(320px, 440px); gap: 40px; align-items: start; }}
          .tool-card, .step-card, .secondary-card {{ display: grid; gap: 16px; padding: 24px; background: var(--surface); border: 1px solid var(--soft-line); border-radius: 8px; }}
          .secondary-card {{ background: #fafafc; }}
          .section-dark .step-card {{ background: #242426; border-color: rgba(255, 255, 255, 0.12); }}
          .section-dark .muted-card {{ opacity: .66; }}
          .auth-grid {{ display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 22px; }}
          .step-grid {{ display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 18px; margin-top: 28px; }}
          .stack-form {{ display: grid; gap: 16px; }}
          .inline-form {{ margin-top: 14px; }}
          label {{ display: grid; gap: 8px; color: var(--muted); font-size: 13px; font-weight: 500; }}
          input {{ width: 100%; min-height: 44px; border: 1px solid var(--line); border-radius: 8px; padding: 10px 12px; color: var(--ink); font: inherit; background: #fff; outline: none; }}
          input:focus {{ border-color: var(--blue); box-shadow: 0 0 0 3px rgba(0, 113, 227, 0.16); }}
          button, .button {{ min-height: 44px; border: 0; border-radius: 999px; padding: 0 20px; display: inline-flex; align-items: center; justify-content: center; gap: 8px; background: var(--blue); color: #fff; font: inherit; font-size: 15px; font-weight: 500; text-decoration: none; cursor: pointer; transition: background .16s ease, transform .16s ease; }}
          button:hover, .button:hover {{ background: var(--blue-hover); }}
          button:active, .button:active {{ transform: scale(.97); }}
          .secondary {{ background: #e8e8ed; color: var(--ink); }}
          .secondary:hover {{ background: #dedee3; }}
          .secondary-on-dark {{ background: transparent; color: #f5f5f7; border: 1px solid rgba(255, 255, 255, 0.36); }}
          .secondary-on-dark:hover {{ background: rgba(255, 255, 255, 0.12); }}
          .danger-button {{ background: transparent; color: var(--danger); border: 1px solid rgba(180, 35, 24, 0.28); }}
          .danger-button:hover {{ background: #fff1f0; }}
          .note {{ margin-top: 10px; color: var(--muted); font-size: 13px; line-height: 1.45; }}
          .copy-list {{ display: grid; gap: 10px; }}
          .copy-row {{ display: grid; grid-template-columns: 150px minmax(0, 1fr) auto; gap: 12px; align-items: center; min-height: 48px; padding: 10px 10px 10px 14px; background: #fff; border: 1px solid var(--soft-line); border-radius: 8px; }}
          .copy-row span {{ color: var(--muted); font-size: 13px; }}
          .copy-row code {{ overflow: hidden; text-overflow: ellipsis; white-space: nowrap; color: var(--ink); font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 13px; }}
          .copy-button {{ min-height: 32px; padding: 0 12px; border-radius: 999px; background: #f5f5f7; color: var(--blue); font-size: 13px; }}
          .copy-button:hover {{ background: #e8e8ed; }}
          .step-number {{ width: 28px; height: 28px; display: inline-flex; align-items: center; justify-content: center; background: var(--blue); color: white; border-radius: 50%; font-size: 13px; }}
          .table-wrap {{ overflow-x: auto; }}
          table {{ width: 100%; border-collapse: collapse; font-size: 14px; font-variant-numeric: tabular-nums; }}
          th, td {{ border-bottom: 1px solid var(--soft-line); padding: 14px 10px; text-align: left; white-space: nowrap; }}
          th {{ color: var(--muted); font-size: 12px; font-weight: 600; }}
          .empty {{ color: var(--muted); text-align: center; padding: 28px; }}
          .icon-button {{ width: 32px; min-height: 32px; padding: 0; background: #f5f5f7; color: var(--danger); }}
          .icon-button:hover {{ background: #fff1f0; }}
          @media (max-width: 860px) {{
            .tool-grid, .auth-grid, .step-grid {{ grid-template-columns: 1fr; }}
            .split-row, .section-heading {{ align-items: flex-start; flex-direction: column; }}
            .section, .hero-band {{ padding: 52px 0; }}
            h1 {{ font-size: 36px; }}
            .lead {{ font-size: 17px; }}
          }}
          @media (max-width: 560px) {{
            .container {{ width: min(100% - 28px, 1040px); }}
            .nav-inner {{ gap: 10px; }}
            .nav-actions {{ gap: 8px; }}
            .nav-label {{ display: none; }}
            .copy-row {{ grid-template-columns: 1fr; }}
            .copy-button {{ width: max-content; }}
            h1 {{ font-size: 31px; }}
          }}
        </style>
        <script>
          document.addEventListener("click", async (event) => {{
            const button = event.target.closest("[data-copy]");
            if (!button) return;
            try {{
              await navigator.clipboard.writeText(button.dataset.copy || "");
              const old = button.textContent;
              button.textContent = "Copied";
              setTimeout(() => {{ button.textContent = old; }}, 1200);
            }} catch (_) {{}}
          }});
        </script>
      </head>
      <body>{body}</body>
    </html>
    """

from __future__ import annotations

import html
import secrets
import sqlite3
import urllib.parse
from typing import Annotated

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request, Response
from fastapi.responses import HTMLResponse, PlainTextResponse, RedirectResponse
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
            "default-src 'self'; style-src 'unsafe-inline' 'self'; form-action 'self'; frame-ancestors 'none'"
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
    def index() -> str:
        return _render_magic_page(service, settings, None, None)

    @app.post("/magic", response_class=HTMLResponse)
    async def magic_account(request: Request) -> str:
        form = _parse_form(await request.body())
        username = _first_form_value(form, "username") or None
        account = await run_in_threadpool(service.create_managed_account, username, None)
        return _render_magic_page(service, settings, account, None)

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
                '<main class="shell"><section class="panel"><h1>Hostname deleted</h1><p class="note">The update URL no longer works.</p></section></main>',
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
        return _render_magic_page(service, settings, None, None, challenge)

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
            return _render_magic_page(service, settings, None, "TXT record not found yet. DNS propagation can take a few minutes.", challenge)
        return _render_magic_page(service, settings, None, "Domain verified. You can now create a hostname under it.", challenge)

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
        return _render_magic_page(service, settings, account, None)

    @app.post("/register")
    async def register(request: Request) -> Response:
        form = _parse_form(await request.body())
        email = normalize_email(_first_form_value(form, "email"))
        password = _first_form_value(form, "password")
        invite = _first_form_value(form, "invite")
        if not email or len(password) < 12:
            return HTMLResponse(_render_public_page(service, settings, None, [], None, "Use a valid email and a password with at least 12 characters."))
        try:
            user = await run_in_threadpool(store.create_user, email, password, invite, settings.require_invite)
        except (sqlite3.IntegrityError, ValueError):
            return HTMLResponse(
                _render_public_page(service, settings, None, [], None, "Registration failed. Check the invite code and email address."),
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
            return HTMLResponse(_render_public_page(service, settings, None, [], None, "Login failed."), status_code=401)
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
    def favicon() -> Response:
        return Response(status_code=204)

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
    suffix = html.escape(settings.hostname_suffix or "your DynDNS domain")
    created_html = _created_account_panel(service, created_account)
    challenge_html = _challenge_panel(service, challenge, message)
    message_html = f'<section class="panel warning-panel"><p>{html.escape(message)}</p></section>' if message and not challenge else ""
    managed_html = ""
    if settings.hostname_suffix:
        managed_html = """
        <section class="panel">
          <h2>Free DynDNS hostname</h2>
          <form method="post" action="/magic" class="account-form">
            <label>Benutzername
              <input name="username" placeholder="optional">
            </label>
            <button type="submit">Generate secure URLs</button>
          </form>
          <p class="note">No account needed. You will receive a random hostname, a router update URL, and a separate magic management link. Keep the management link private.</p>
        </section>
        """

    return _page(
        "DynDNS",
        f"""
        <main class="shell">
          <section class="hero">
            <div>
              <p class="eyebrow">FRITZ!Box compatible</p>
              <h1>Free DynDNS for {suffix}</h1>
              <p class="lead">Generate cryptographically random URLs, paste the update URL into your router, and keep the management link somewhere safe.</p>
            </div>
            <a class="button secondary" href="/admin">Admin</a>
          </section>
          {message_html}
          {created_html}
          {managed_html}
          {challenge_html}
        </main>
        """,
    )


def _render_management_page(service: DdnsService, settings: DdnsSettings, management_slug: str, account: dict[str, str | int | None]) -> str:
    account_for_url = {
        "hostname": str(account["hostname"]),
        "username": str(account["username"]),
        "password": "",
        "update_slug": str(account["update_slug"]),
        "management_slug": management_slug,
    }
    update_url = html.escape(service.fritz_update_url(account_for_url))
    hostname = html.escape(str(account["hostname"]))
    username = html.escape(str(account["username"]))
    ipv4 = html.escape(str(account.get("ipv4") or "-"))
    ipv6 = html.escape(str(account.get("ipv6") or "-"))
    updated = html.escape(str(account.get("updated_at") or "Never"))
    return _page(
        "DynDNS management",
        f"""
        <main class="shell">
          <section class="hero">
            <div>
              <p class="eyebrow">Magic management</p>
              <h1>{hostname}</h1>
              <p class="lead">Anyone with this link can manage this hostname. Keep it private.</p>
            </div>
            <a class="button secondary" href="/">Home</a>
          </section>
          <section class="panel">
            <h2>FRITZ!Box fields</h2>
            <div class="fritz-form">
              <label>Update-URL:<input readonly value="{update_url}"></label>
              <label>Domainnamen:<input readonly value="{hostname}"></label>
              <label>Benutzername:<input readonly value="{username}"></label>
              <label>Kennwort:<input readonly value="unchanged; only shown when generated"></label>
            </div>
          </section>
          <section class="panel">
            <h2>Current IP</h2>
            <table>
              <tbody>
                <tr><th>IPv4</th><td>{ipv4}</td></tr>
                <tr><th>IPv6</th><td>{ipv6}</td></tr>
                <tr><th>Updated</th><td>{updated}</td></tr>
              </tbody>
            </table>
            <form method="post" action="/m/{html.escape(management_slug)}/delete" class="inline-form">
              <button type="submit">Delete hostname</button>
            </form>
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
    suffix = html.escape(settings.hostname_suffix or "your domain")
    message_html = f'<section class="panel warning-panel"><p>{html.escape(message)}</p></section>' if message else ""
    if not user:
        invite_field = """
          <label>Invite code
            <input name="invite" autocomplete="off" required>
          </label>
        """ if settings.require_invite else ""
        return _page(
            "DynDNS",
            f"""
            <main class="shell">
              <section class="hero">
                <div>
                  <p class="eyebrow">FRITZ!Box compatible</p>
                  <h1>Managed DynDNS for {suffix}</h1>
                  <p class="lead">Create a secure update URL for your FRITZ!Box or router. Sign in to generate provider hostnames or verify your own domain with DNS.</p>
                </div>
                <a class="button" href="/admin">Admin</a>
              </section>
              {message_html}
              <section class="panel auth-grid">
                <div>
                  <h2>Login</h2>
                  <form method="post" action="/login" class="stack-form">
                    <label>Email<input name="email" type="email" autocomplete="email" required></label>
                    <label>Password<input name="password" type="password" autocomplete="current-password" required></label>
                    <button type="submit">Login</button>
                  </form>
                </div>
                <div>
                  <h2>Register</h2>
                  <form method="post" action="/register" class="stack-form">
                    <label>Email<input name="email" type="email" autocomplete="email" required></label>
                    <label>Password<input name="password" type="password" autocomplete="new-password" minlength="12" required></label>
                    {invite_field}
                    <button type="submit">Create account</button>
                  </form>
                </div>
              </section>
            </main>
            """,
        )
    return _render_magic_page(service, settings, created_account, message, challenge)


def _challenge_panel(service: DdnsService, challenge: dict[str, str | None] | None, message: str | None) -> str:
    challenge_html = ""
    claim_secret = ""
    if challenge:
        domain = html.escape(str(challenge["domain"]))
        token = html.escape(str(challenge["token"]))
        claim_secret = html.escape(str(challenge.get("claim_secret") or ""))
        verification_name = html.escape(service.verification_name(str(challenge["domain"])))
        status = html.escape(message or "Add this TXT record, then verify.")
        challenge_html = f"""
        <div class="dns-challenge">
          <p class="note">{status}</p>
          <div class="fritz-form">
            <label>TXT name<input readonly value="{verification_name}"></label>
            <label>TXT value<input readonly value="{token}"></label>
          </div>
          <form method="post" action="/verify-domain" class="inline-form">
            <input type="hidden" name="domain" value="{domain}">
            <input type="hidden" name="claim_secret" value="{claim_secret}">
            <button type="submit">Verify DNS</button>
          </form>
        </div>
        """

    return f"""
    <section class="panel">
      <h2>Custom domain</h2>
      <form method="post" action="/request-domain" class="account-form">
        <label>Domain to verify
          <input name="domain" placeholder="example.com" required>
        </label>
        <button type="submit">Create TXT challenge</button>
      </form>
      {challenge_html}
      <form method="post" action="/accounts" class="account-form stacked">
        <input type="hidden" name="mode" value="custom">
        <input type="hidden" name="claim_secret" value="{claim_secret}">
        <label>Verified hostname
          <input name="hostname" placeholder="home.example.com" required>
        </label>
        <label>Benutzername
          <input name="username" placeholder="optional">
        </label>
        <button type="submit">Generate credentials</button>
      </form>
      <p class="note">The hostname must be inside a domain that has already passed TXT verification.</p>
    </section>
    """


def _created_account_panel(service: DdnsService, created_account: dict[str, str] | None) -> str:
    if not created_account:
        return ""
    hostname = html.escape(created_account["hostname"])
    username = html.escape(created_account["username"])
    password = html.escape(created_account["password"])
    update_url = html.escape(service.fritz_update_url(created_account))
    management_url = html.escape(service.magic_management_url(created_account))
    return f"""
    <section class="panel success-panel">
      <div>
        <p class="eyebrow">Account generated</p>
        <h2>{hostname}</h2>
      </div>
      <div class="fritz-form">
        <label>Update-URL:<input readonly value="{update_url}"></label>
        <label>Domainnamen:<input readonly value="{hostname}"></label>
        <label>Benutzername:<input readonly value="{username}"></label>
        <label>Kennwort:<input readonly value="{password}"></label>
        <label>Magic management link:<input readonly value="{management_url}"></label>
      </div>
      <p class="note">Save this now. The password and management link are only shown on this screen. The Update-URL and management link are separate cryptographically random bearer URLs.</p>
    </section>
    """


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
        <main class="shell">
          <section class="topbar">
            <div>
              <p class="eyebrow">DynDNS aktiv</p>
              <h1>FRITZ!Box accounts</h1>
            </div>
            <div class="button-row">
              <a class="button secondary" href="/records">JSON records</a>
              <a class="button secondary" href="/events">Update events</a>
            </div>
          </section>

          {_created_account_panel(service, created_account)}

          <section class="panel">
            <h2>Invites</h2>
            <form method="post" action="/admin/invites" class="inline-form">
              <input type="hidden" name="csrf" value="{csrf}">
              <button type="submit">Create invite</button>
            </form>
            <div class="table-wrap">
              <table>
                <thead><tr><th>Code</th><th>Created</th><th>Used</th></tr></thead>
                <tbody>{invite_rows}</tbody>
              </table>
            </div>
          </section>

          <section class="panel">
            <h2>Generate account</h2>
            <p class="intro">Geben Sie die Anmeldedaten für Ihren DynDNS-Anbieter an. Generated accounts produce the FRITZ!Box fields: Update-URL, Domainnamen, Benutzername, Kennwort.</p>
            <form method="post" action="/admin/accounts" class="account-form">
              <input type="hidden" name="csrf" value="{csrf}">
              <label>Domainnamen
                <input name="hostname" placeholder="home.example.net" required>
              </label>
              <label>Benutzername
                <input name="username" placeholder="auto-generated">
              </label>
              <button type="submit">Generate</button>
            </form>
            <p class="note">{suffix_help}</p>
          </section>

          <section class="panel">
            <h2>Accounts</h2>
            <div class="table-wrap">
              <table>
                <thead>
                  <tr><th>Domain</th><th>User</th><th>Owner</th><th>IPv4</th><th>IPv6</th><th>Updated</th><th></th></tr>
                </thead>
                <tbody>{rows}</tbody>
              </table>
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
        <style>
          :root {{
            color-scheme: light;
            --bg: #f6f7f9;
            --text: #18202a;
            --muted: #667085;
            --line: #d9dee7;
            --panel: #ffffff;
            --accent: #1769aa;
            --accent-strong: #0f548b;
            --good: #e9f7ef;
            --good-line: #9fd6b2;
          }}
          * {{ box-sizing: border-box; }}
          body {{
            margin: 0;
            min-height: 100vh;
            background: var(--bg);
            color: var(--text);
            font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
          }}
          .shell {{ width: min(1120px, calc(100% - 32px)); margin: 0 auto; padding: 32px 0; }}
          .hero, .topbar {{ display: flex; align-items: flex-end; justify-content: space-between; gap: 24px; padding: 28px 0; }}
          .button-row {{ display: flex; gap: 10px; flex-wrap: wrap; }}
          h1, h2, p {{ margin: 0; }}
          h1 {{ font-size: 34px; line-height: 1.15; font-weight: 700; letter-spacing: 0; }}
          h2 {{ font-size: 19px; line-height: 1.3; margin-bottom: 18px; }}
          .eyebrow {{ margin-bottom: 8px; color: var(--accent); font-size: 13px; font-weight: 700; text-transform: uppercase; }}
          .lead {{ max-width: 620px; margin-top: 12px; color: var(--muted); font-size: 17px; line-height: 1.5; }}
          .intro {{ margin: -6px 0 18px; color: var(--muted); font-size: 14px; line-height: 1.5; }}
          .panel {{ background: var(--panel); border: 1px solid var(--line); border-radius: 8px; padding: 22px; margin: 18px 0; }}
          .success-panel {{ background: var(--good); border-color: var(--good-line); }}
          .warning-panel {{ background: #fff8e6; border-color: #f0cc74; }}
          .account-form, .fritz-form {{ display: grid; grid-template-columns: minmax(0, 1fr) minmax(180px, 260px) auto; gap: 14px; align-items: end; }}
          .auth-grid {{ display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 22px; }}
          .stack-form {{ display: grid; gap: 14px; }}
          .inline-form {{ margin-top: 14px; }}
          .fritz-form {{ grid-template-columns: 1fr; margin-top: 18px; }}
          label {{ display: grid; gap: 7px; color: var(--muted); font-size: 13px; font-weight: 650; }}
          input {{ width: 100%; min-height: 42px; border: 1px solid var(--line); border-radius: 6px; padding: 9px 11px; color: var(--text); font: inherit; background: #fff; }}
          input[readonly] {{ background: #f9fafb; }}
          button, .button {{ min-height: 42px; border: 0; border-radius: 6px; padding: 0 16px; display: inline-flex; align-items: center; justify-content: center; background: var(--accent); color: #fff; font: inherit; font-weight: 700; text-decoration: none; cursor: pointer; }}
          button:hover, .button:hover {{ background: var(--accent-strong); }}
          .secondary {{ background: #344054; }}
          .note {{ margin-top: 12px; color: var(--muted); font-size: 13px; line-height: 1.45; }}
          .table-wrap {{ overflow-x: auto; }}
          table {{ width: 100%; border-collapse: collapse; font-size: 14px; }}
          th, td {{ border-bottom: 1px solid var(--line); padding: 12px 10px; text-align: left; white-space: nowrap; }}
          th {{ color: var(--muted); font-size: 12px; text-transform: uppercase; }}
          .empty {{ color: var(--muted); text-align: center; padding: 28px; }}
          .icon-button {{ width: 32px; min-height: 32px; padding: 0; background: #eef1f5; color: #344054; }}
          .icon-button:hover {{ background: #dce3ec; }}
          @media (max-width: 760px) {{
            .hero, .topbar {{ align-items: flex-start; flex-direction: column; }}
            .account-form, .auth-grid {{ grid-template-columns: 1fr; }}
            h1 {{ font-size: 28px; }}
          }}
        </style>
      </head>
      <body>{body}</body>
    </html>
    """

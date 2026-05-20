from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
from datetime import UTC, datetime
from ipaddress import ip_address, ip_network

from fastapi import HTTPException, Request

from .ddns_models import DdnsSettings


def credentials_from_basic_auth(header: str) -> tuple[str | None, str | None]:
    try:
        raw = base64.b64decode(header.split(" ", 1)[1]).decode("utf-8")
    except Exception:
        return None, None
    if ":" not in raw:
        return None, None
    username, password = raw.split(":", 1)
    return username, password


def hash_secret(token: str) -> str:
    salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", token.encode("utf-8"), salt.encode("ascii"), 200_000)
    return f"pbkdf2_sha256${salt}${digest.hex()}"


def verify_secret(token: str, stored: str) -> bool:
    try:
        algorithm, salt, expected = stored.split("$", 2)
    except ValueError:
        return False
    if algorithm != "pbkdf2_sha256":
        return False
    digest = hashlib.pbkdf2_hmac("sha256", token.encode("utf-8"), salt.encode("ascii"), 200_000)
    return hmac.compare_digest(digest.hex(), expected)


def hash_lookup_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def admin_csrf_token(settings: DdnsSettings) -> str:
    secret = settings.admin_password or settings.shared_secret
    day = datetime.now(UTC).strftime("%Y-%m-%d")
    return hmac.new(secret.encode("utf-8"), f"admin:{day}".encode(), hashlib.sha256).hexdigest()


def require_admin_csrf(settings: DdnsSettings, supplied: str) -> None:
    if not supplied or not hmac.compare_digest(supplied, admin_csrf_token(settings)):
        raise HTTPException(status_code=403, detail="invalid csrf token")


def client_ip(request: Request, settings: DdnsSettings | None = None) -> str:
    peer = request.client.host if request.client else "unknown"
    forwarded = request.headers.get("x-forwarded-for", "")
    if forwarded and settings and _trusted_proxy(peer, settings.trusted_proxy_ips):
        return forwarded.split(",", 1)[0].strip()
    return peer


def is_rate_limited_path(path: str) -> bool:
    limited_paths = {
        "/magic",
        "/accounts",
        "/request-domain",
        "/verify-domain",
        "/nic/update",
    }
    return path in limited_paths or path.startswith(("/u/", "/api/v1/updates/")) or path.startswith(
        ("/api/v1/hostnames/", "/api/v1/domains/")
    )


def _trusted_proxy(peer: str, trusted: set[str]) -> bool:
    if not trusted:
        return False
    try:
        peer_ip = ip_address(peer)
    except ValueError:
        return False
    for candidate in trusted:
        try:
            if "/" in candidate and peer_ip in ip_network(candidate, strict=False):
                return True
            if "/" not in candidate and peer_ip == ip_address(candidate):
                return True
        except ValueError:
            continue
    return False

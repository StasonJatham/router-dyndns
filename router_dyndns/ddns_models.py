from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from pydantic import BaseModel, Field, field_validator


class DdnsSettings(BaseModel):
    database_path: Path = Field(default=Path("ddns.sqlite3"))
    shared_secret: str = Field(default="")
    admin_password: str = Field(default="")
    allowed_hosts: set[str] = Field(default_factory=set)
    public_base_url: str = Field(default="http://localhost:8080")
    hostname_suffix: str = Field(default="")
    verification_prefix: str = Field(default="_router_dyndns-ddns")
    rate_limit_per_minute: int = Field(default=60, ge=1, le=10_000)
    trusted_proxy_ips: set[str] = Field(default_factory=set)
    rfc2136_server: str | None = None
    rfc2136_zone: str | None = None
    rfc2136_key_name: str | None = None
    rfc2136_key_secret: str | None = None
    dns_provider: str = Field(default="")
    dns_zones: set[str] = Field(default_factory=set)
    require_dns_provider: bool = Field(default=False)
    cloudflare_api_token: str = Field(default="")
    cloudflare_zone_id: str = Field(default="")
    cleanup_challenge_hours: int = Field(default=72, ge=1, le=24 * 365)
    ttl: int = Field(default=60, ge=60, le=86400)

    @field_validator("public_base_url")
    @classmethod
    def validate_public_base_url(cls, value: str) -> str:
        if not value.startswith(("http://", "https://")):
            raise ValueError("public_base_url must start with http:// or https://")
        return value.rstrip("/")

    @classmethod
    def from_env(cls) -> DdnsSettings:
        allowed = {
            item.strip().lower()
            for item in os.getenv("DDNS_ALLOWED_HOSTS", "").split(",")
            if item.strip()
        }
        trusted_proxy_ips = _csv_set("DDNS_TRUSTED_PROXY_IPS")
        dns_zones = _csv_set("DDNS_DNS_ZONES")
        return cls(
            database_path=Path(os.getenv("DDNS_DATABASE", "ddns.sqlite3")),
            shared_secret=os.getenv("DDNS_SHARED_SECRET", ""),
            admin_password=os.getenv("DDNS_ADMIN_PASSWORD", os.getenv("DDNS_SHARED_SECRET", "")),
            allowed_hosts=allowed,
            public_base_url=os.getenv("DDNS_PUBLIC_BASE_URL", "http://localhost:8080"),
            hostname_suffix=os.getenv("DDNS_HOSTNAME_SUFFIX", ""),
            verification_prefix=os.getenv("DDNS_VERIFICATION_PREFIX", "_router_dyndns-ddns"),
            rate_limit_per_minute=_env_int("DDNS_RATE_LIMIT_PER_MINUTE", 60),
            trusted_proxy_ips=trusted_proxy_ips,
            rfc2136_server=os.getenv("DDNS_RFC2136_SERVER") or None,
            rfc2136_zone=os.getenv("DDNS_RFC2136_ZONE") or None,
            rfc2136_key_name=os.getenv("DDNS_RFC2136_KEY_NAME") or None,
            rfc2136_key_secret=os.getenv("DDNS_RFC2136_KEY_SECRET") or None,
            dns_provider=os.getenv("DDNS_DNS_PROVIDER", ""),
            dns_zones=dns_zones,
            require_dns_provider=os.getenv("DDNS_REQUIRE_DNS_PROVIDER", "0").strip().lower() not in {"0", "false", "no"},
            cloudflare_api_token=os.getenv("DDNS_CLOUDFLARE_API_TOKEN", ""),
            cloudflare_zone_id=os.getenv("DDNS_CLOUDFLARE_ZONE_ID", ""),
            cleanup_challenge_hours=_env_int("DDNS_CLEANUP_CHALLENGE_HOURS", 72),
            ttl=_env_int("DDNS_TTL", 60),
        )


@dataclass(slots=True)
class UpdateResult:
    hostname: str
    ipv4: str | None
    ipv6: str | None
    changed: bool
    update_ipv4: bool = True
    update_ipv6: bool = True

    @property
    def dyndns_response(self) -> str:
        ip = self.ipv4 or self.ipv6 or "0.0.0.0"
        return f"{'good' if self.changed else 'nochg'} {ip}"


def _csv_set(name: str) -> set[str]:
    return {item.strip().lower() for item in os.getenv(name, "").split(",") if item.strip()}


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, str(default)))
    except ValueError:
        return default

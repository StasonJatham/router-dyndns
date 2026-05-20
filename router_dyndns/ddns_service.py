from __future__ import annotations

import ipaddress
import re
import secrets
import sqlite3
import threading
import urllib.parse
from dataclasses import dataclass

from fastapi import HTTPException, Request

from .ddns_dns import delete_dns_records, dns_backend_configured, publish_dns
from .ddns_models import DdnsSettings, UpdateResult
from .ddns_security import client_ip
from .ddns_store import DdnsStore


@dataclass(slots=True)
class UpdateOutcome:
    result: UpdateResult
    source_ip: str


class DdnsService:
    def __init__(self, settings: DdnsSettings, store: DdnsStore) -> None:
        self.settings = settings
        self.store = store
        self._locks_guard = threading.Lock()
        self._locks: dict[str, threading.Lock] = {}

    def create_managed_account(self, username: str | None = None, owner_user_id: int | None = None) -> dict[str, str]:
        if not self.settings.hostname_suffix:
            raise HTTPException(status_code=500, detail="DDNS_HOSTNAME_SUFFIX is required")
        if owner_user_id is not None:
            self._enforce_account_quota(owner_user_id)
        for _ in range(5):
            try:
                return self.store.create_account(
                    self.random_managed_hostname(),
                    username,
                    owner_user_id=owner_user_id,
                )
            except sqlite3.IntegrityError:
                continue
        raise HTTPException(status_code=500, detail="could not allocate hostname")

    def create_custom_account(
        self,
        hostname: str,
        claim_secret: str,
        username: str | None = None,
        owner_user_id: int | None = None,
    ) -> dict[str, str]:
        normalized = normalize_hostname(hostname, self.settings, expand_suffix=False)
        if not normalized:
            raise HTTPException(status_code=400, detail="valid custom hostname is required")
        if not self.hostname_is_publishable(normalized):
            raise HTTPException(status_code=403, detail="hostname is outside configured DNS publishing zones")
        if not self.best_verified_parent(normalized, owner_user_id, claim_secret):
            raise HTTPException(status_code=403, detail="verify the parent domain before creating this hostname")
        if owner_user_id is not None:
            self._enforce_account_quota(owner_user_id)
        try:
            return self.store.create_account(normalized, username, owner_user_id=owner_user_id)
        except sqlite3.IntegrityError as exc:
            raise HTTPException(status_code=409, detail="hostname already exists") from exc

    def create_domain_challenge(self, domain: str, owner_user_id: int | None = None) -> dict[str, str]:
        normalized = normalize_domain(domain)
        if not normalized:
            raise HTTPException(status_code=400, detail="valid domain is required")
        existing = self.store.get_domain_challenge(normalized, owner_user_id=owner_user_id)
        if existing and existing.get("verified_at"):
            raise HTTPException(status_code=409, detail="domain is already verified")
        return self.store.create_domain_challenge(normalized, owner_user_id)

    def verify_domain(self, domain: str, claim_secret: str, owner_user_id: int | None = None) -> tuple[bool, dict[str, str | None]]:
        normalized = normalize_domain(domain)
        if not normalized:
            raise HTTPException(status_code=400, detail="valid domain is required")
        challenge = self.store.get_domain_challenge(normalized, owner_user_id=owner_user_id, claim_secret=claim_secret)
        if not challenge:
            raise HTTPException(status_code=404, detail="domain challenge not found")
        found = dns_txt_contains(self.verification_name(normalized), str(challenge["token"]))
        if not found:
            challenge = dict(challenge)
            challenge["claim_secret"] = claim_secret
            return False, challenge
        verified = self.store.verify_domain_challenge(normalized, owner_user_id=owner_user_id)
        if verified is None:
            raise HTTPException(status_code=404, detail="domain challenge not found")
        verified = dict(verified)
        verified["claim_secret"] = claim_secret
        return True, verified

    def delete_account(self, hostname: str, source: str) -> None:
        try:
            delete_dns_records(hostname, self.settings)
        except Exception as exc:
            self.store.log_update_event(hostname, None, None, "dns_delete_failed", f"{type(exc).__name__}: {exc}", source)
            raise
        self.store.delete_account(hostname)

    def apply_update(
        self,
        request: Request,
        hostname: str,
        myip: str | None,
        ipaddr: str | None,
        myipv6: str | None,
        ip6addr: str | None,
    ) -> UpdateOutcome:
        ipv4, ipv6, update_ipv4, update_ipv6 = parse_update_ips(request, myip, ipaddr, myipv6, ip6addr)
        source_ip = client_ip(request, self.settings)
        lock = self._lock_for(hostname)
        with lock:
            planned = self.store.preview_update(hostname, ipv4, ipv6, update_ipv4=update_ipv4, update_ipv6=update_ipv6)
            if planned.changed:
                try:
                    publish_dns(planned, self.settings)
                except Exception as exc:
                    self.store.log_update_event(hostname, ipv4, ipv6, "dns_failed", f"{type(exc).__name__}: {exc}", source_ip)
                    raise
            result = self.store.upsert(hostname, ipv4, ipv6, update_ipv4=update_ipv4, update_ipv6=update_ipv6)
            self.store.log_update_event(hostname, result.ipv4, result.ipv6, "updated" if result.changed else "unchanged", "ok", source_ip)
        return UpdateOutcome(result=result, source_ip=source_ip)

    def fritz_update_url(self, account: dict[str, str]) -> str:
        base = self.settings.public_base_url.rstrip("/")
        slug = urllib.parse.quote(account["update_slug"])
        return f"{base}/u/{slug}?myip=<ipaddr>&myipv6=<ip6addr>"

    def magic_management_url(self, account: dict[str, str]) -> str:
        base = self.settings.public_base_url.rstrip("/")
        slug = urllib.parse.quote(account["management_slug"])
        return f"{base}/m/{slug}"

    def domain_claim_url(self, challenge: dict[str, str | None]) -> str:
        base = self.settings.public_base_url.rstrip("/")
        secret = urllib.parse.quote(str(challenge["claim_secret"]))
        return f"{base}/d/{secret}"

    def random_managed_hostname(self) -> str:
        suffix = self.settings.hostname_suffix.strip().lower().strip(".")
        if not suffix:
            raise HTTPException(status_code=500, detail="DDNS_HOSTNAME_SUFFIX is required for managed hostnames")
        return f"{secrets.token_hex(6)}.{suffix}"

    def best_verified_parent(
        self,
        hostname: str,
        owner_user_id: int | None = None,
        claim_secret: str | None = None,
    ) -> str | None:
        labels = hostname.split(".")
        for index in range(1, len(labels) - 1):
            candidate = ".".join(labels[index:])
            if self.store.is_domain_verified(candidate, owner_user_id, claim_secret):
                return candidate
        if self.store.is_domain_verified(hostname, owner_user_id, claim_secret):
            return hostname
        return None

    def verification_name(self, domain: str) -> str:
        prefix = self.settings.verification_prefix.strip().strip(".") or "_router_dyndns-ddns"
        return f"{prefix}.{domain}"

    def hostname_is_publishable(self, hostname: str) -> bool:
        if not dns_backend_configured(self.settings):
            return not self.settings.require_dns_provider
        zones = {
            zone.strip().lower().strip(".")
            for zone in self.settings.dns_zones
            if zone.strip()
        }
        if not zones and self.settings.rfc2136_zone:
            zones.add(self.settings.rfc2136_zone.strip().lower().strip("."))
        if not zones and self.settings.hostname_suffix:
            zones.add(self.settings.hostname_suffix.strip().lower().strip("."))
        return bool(zones) and any(hostname == zone or hostname.endswith(f".{zone}") for zone in zones)

    def _enforce_account_quota(self, owner_user_id: int) -> None:
        if self.store.count_user_accounts(owner_user_id) >= self.settings.max_hostnames_per_user:
            raise HTTPException(status_code=403, detail="hostname quota exceeded")

    def _lock_for(self, hostname: str) -> threading.Lock:
        with self._locks_guard:
            lock = self._locks.get(hostname)
            if lock is None:
                lock = threading.Lock()
                self._locks[hostname] = lock
            return lock


def normalize_ip(value: str | None, version: int | None = None) -> str | None:
    if not value:
        return None
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return None
    if version and ip.version != version:
        return None
    return str(ip)


def parse_update_ips(
    request: Request,
    myip: str | None,
    ipaddr: str | None,
    myipv6: str | None,
    ip6addr: str | None,
) -> tuple[str | None, str | None, bool, bool]:
    raw_ipv4 = myip if myip is not None else ipaddr
    raw_ipv6 = myipv6 if myipv6 is not None else ip6addr
    update_ipv4 = raw_ipv4 is not None
    update_ipv6 = raw_ipv6 is not None
    ipv4 = normalize_ip(raw_ipv4, version=4)
    ipv6 = normalize_ip(raw_ipv6, version=6)
    if not update_ipv4 and not update_ipv6:
        peer = request.client.host if request.client else None
        ipv4 = normalize_ip(peer, version=4)
        ipv6 = normalize_ip(peer, version=6)
        update_ipv4 = ipv4 is not None
        update_ipv6 = ipv6 is not None
    return ipv4, ipv6, update_ipv4, update_ipv6


def normalize_hostname(value: str, settings: DdnsSettings, expand_suffix: bool = True) -> str:
    hostname = value.strip().lower().rstrip(".")
    suffix = settings.hostname_suffix.strip().lower().strip(".")
    if expand_suffix and suffix and "." not in hostname:
        hostname = f"{hostname}.{suffix}"
    label = r"[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?"
    if not re.fullmatch(rf"{label}(\.{label})+", hostname):
        return ""
    return hostname


def normalize_domain(value: str) -> str:
    return normalize_hostname(value, DdnsSettings(), expand_suffix=False)


def dns_txt_contains(name: str, expected: str) -> bool:
    try:
        import dns.resolver

        answers = dns.resolver.resolve(name, "TXT", lifetime=5)
    except Exception:
        return False
    for answer in answers:
        for item in answer.strings:
            if item.decode("utf-8", errors="replace") == expected:
                return True
    return False

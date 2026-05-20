from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request

from .ddns_models import DdnsSettings, UpdateResult


def publish_dns(result: UpdateResult, settings: DdnsSettings) -> None:
    provider = settings.dns_provider.strip().lower()
    if provider == "cloudflare":
        publish_cloudflare(result, settings)
        return
    if settings.rfc2136_server or provider == "rfc2136":
        publish_rfc2136(result, settings)
        return
    if settings.require_dns_provider:
        raise RuntimeError("DNS provider is required but not configured")


def delete_dns_records(hostname: str, settings: DdnsSettings) -> None:
    provider = settings.dns_provider.strip().lower()
    if provider == "cloudflare":
        delete_cloudflare_records(hostname, settings)
        return
    if settings.rfc2136_server or provider == "rfc2136":
        delete_rfc2136_records(hostname, settings)
        return
    if settings.require_dns_provider:
        raise RuntimeError("DNS provider is required but not configured")


def dns_backend_configured(settings: DdnsSettings) -> bool:
    provider = settings.dns_provider.strip().lower()
    return provider == "cloudflare" or provider == "rfc2136" or bool(settings.rfc2136_server)


def publish_rfc2136(result: UpdateResult, settings: DdnsSettings) -> None:
    if not settings.rfc2136_server:
        return

    import dns.query
    import dns.tsigkeyring
    import dns.update

    keyring = None
    if settings.rfc2136_key_name and settings.rfc2136_key_secret:
        keyring = dns.tsigkeyring.from_text({settings.rfc2136_key_name: settings.rfc2136_key_secret})

    zone = settings.rfc2136_zone or ".".join(result.hostname.split(".")[1:])
    update = dns.update.Update(zone, keyring=keyring)
    relative = result.hostname.removesuffix("." + zone).rstrip(".") or "@"
    if result.update_ipv4 and result.ipv4:
        update.replace(relative, settings.ttl, "A", result.ipv4)
    elif result.update_ipv4:
        update.delete(relative, "A")
    if result.update_ipv6 and result.ipv6:
        update.replace(relative, settings.ttl, "AAAA", result.ipv6)
    elif result.update_ipv6:
        update.delete(relative, "AAAA")
    response = dns.query.tcp(update, settings.rfc2136_server, timeout=5)
    rcode = response.rcode()
    if rcode != 0:
        import dns.rcode

        raise RuntimeError(f"RFC2136 update failed: {dns.rcode.to_text(rcode)}")


def delete_rfc2136_records(hostname: str, settings: DdnsSettings) -> None:
    if not settings.rfc2136_server:
        return

    import dns.query
    import dns.tsigkeyring
    import dns.update

    keyring = None
    if settings.rfc2136_key_name and settings.rfc2136_key_secret:
        keyring = dns.tsigkeyring.from_text({settings.rfc2136_key_name: settings.rfc2136_key_secret})

    zone = settings.rfc2136_zone or ".".join(hostname.split(".")[1:])
    update = dns.update.Update(zone, keyring=keyring)
    relative = hostname.removesuffix("." + zone).rstrip(".") or "@"
    update.delete(relative, "A")
    update.delete(relative, "AAAA")
    dns.query.tcp(update, settings.rfc2136_server, timeout=5)


def publish_cloudflare(result: UpdateResult, settings: DdnsSettings) -> None:
    if not settings.cloudflare_api_token or not settings.cloudflare_zone_id:
        raise RuntimeError("DDNS_CLOUDFLARE_API_TOKEN and DDNS_CLOUDFLARE_ZONE_ID are required")
    if result.update_ipv4:
        _cloudflare_upsert_record(settings, result.hostname, "A", result.ipv4)
    if result.update_ipv6:
        _cloudflare_upsert_record(settings, result.hostname, "AAAA", result.ipv6)


def delete_cloudflare_records(hostname: str, settings: DdnsSettings) -> None:
    if not settings.cloudflare_api_token or not settings.cloudflare_zone_id:
        raise RuntimeError("DDNS_CLOUDFLARE_API_TOKEN and DDNS_CLOUDFLARE_ZONE_ID are required")
    for record_type in ("A", "AAAA"):
        record = _cloudflare_find_record(settings, hostname, record_type)
        if record:
            _cloudflare_request(settings, f"/dns_records/{record['id']}", method="DELETE")


def _cloudflare_upsert_record(settings: DdnsSettings, hostname: str, record_type: str, value: str | None) -> None:
    record = _cloudflare_find_record(settings, hostname, record_type)
    if value is None:
        if record:
            _cloudflare_request(settings, f"/dns_records/{record['id']}", method="DELETE")
        return

    payload = {
        "type": record_type,
        "name": hostname,
        "content": value,
        "ttl": settings.ttl,
        "proxied": False,
    }
    if record:
        _cloudflare_request(settings, f"/dns_records/{record['id']}", method="PATCH", payload=payload)
    else:
        _cloudflare_request(settings, "/dns_records", method="POST", payload=payload)


def _cloudflare_find_record(settings: DdnsSettings, hostname: str, record_type: str) -> dict[str, str] | None:
    query = urllib.parse.urlencode({"type": record_type, "name": hostname})
    response = _cloudflare_request(settings, f"/dns_records?{query}")
    records = response.get("result", [])
    return records[0] if records else None


def _cloudflare_request(
    settings: DdnsSettings,
    path: str,
    method: str = "GET",
    payload: dict[str, object] | None = None,
) -> dict[str, object]:
    url = f"https://api.cloudflare.com/client/v4/zones/{settings.cloudflare_zone_id}{path}"
    body = json.dumps(payload).encode("utf-8") if payload is not None else None
    request = urllib.request.Request(url, data=body, method=method)
    request.add_header("Authorization", f"Bearer {settings.cloudflare_api_token}")
    request.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            parsed = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"Cloudflare API {exc.code}: {detail}") from exc
    if not parsed.get("success", False):
        raise RuntimeError(f"Cloudflare API error: {parsed}")
    return parsed

import re
import time
from pathlib import Path

from fastapi.testclient import TestClient

import router_dyndns.ddns_service as ddns_service
from router_dyndns.ddns import DdnsSettings, DdnsStore, make_app
from router_dyndns.ddns_security import admin_csrf_token


def test_update_accepts_fritzbox_placeholders(tmp_path: Path) -> None:
    app = make_app(
        DdnsSettings(
            database_path=tmp_path / "ddns.sqlite3",
            shared_secret="secret",
            allowed_hosts={"home.example.net"},
        )
    )
    client = TestClient(app)

    response = client.get(
        "/nic/update",
        params={
            "hostname": "home.example.net",
            "myip": "203.0.113.8",
            "myipv6": "2001:db8::8",
            "password": "secret",
        },
    )

    assert response.status_code == 200
    assert response.text == "good 203.0.113.8"
    records = client.get("/records", auth=("admin", "secret")).json()
    assert records[0]["hostname"] == "home.example.net"
    assert records[0]["ipv4"] == "203.0.113.8"
    assert records[0]["ipv6"] == "2001:db8::8"


def test_update_rejects_wrong_secret(tmp_path: Path) -> None:
    app = make_app(DdnsSettings(database_path=tmp_path / "ddns.sqlite3", shared_secret="secret"))
    client = TestClient(app)

    response = client.get(
        "/nic/update",
        params={"hostname": "home.example.net", "myip": "203.0.113.8", "password": "wrong"},
    )

    assert response.status_code == 401


def test_update_rejects_unlisted_host(tmp_path: Path) -> None:
    app = make_app(
        DdnsSettings(
            database_path=tmp_path / "ddns.sqlite3",
            shared_secret="secret",
            allowed_hosts={"home.example.net"},
        )
    )
    client = TestClient(app)

    response = client.get(
        "/nic/update",
        params={"hostname": "other.example.net", "myip": "203.0.113.8", "password": "secret"},
    )

    assert response.status_code == 403


def test_generated_account_can_update_own_hostname(tmp_path: Path) -> None:
    database_path = tmp_path / "ddns.sqlite3"
    store = DdnsStore(database_path)
    account = store.create_account("home.example.net", "alice")
    app = make_app(DdnsSettings(database_path=database_path, admin_password="admin"))
    client = TestClient(app)

    response = client.get(
        "/nic/update",
        params={
            "hostname": "home.example.net",
            "myip": "203.0.113.9",
            "username": account["username"],
            "password": account["password"],
        },
    )

    assert response.status_code == 200
    assert response.text == "good 203.0.113.9"

    slug_response = client.get(
        f"/u/{account['update_slug']}",
        params={"myip": "203.0.113.10"},
    )

    assert slug_response.status_code == 200
    assert slug_response.text == "good 203.0.113.10"


def test_dns_publish_failure_does_not_update_record(tmp_path: Path, monkeypatch) -> None:
    def fail_publish(result, settings):
        raise RuntimeError("dns down")

    monkeypatch.setattr(ddns_service, "publish_dns", fail_publish)
    database_path = tmp_path / "ddns.sqlite3"
    store = DdnsStore(database_path)
    account = store.create_account("home.example.net", "alice")
    app = make_app(DdnsSettings(database_path=database_path, admin_password="admin"))
    client = TestClient(app)

    response = client.get(f"/u/{account['update_slug']}", params={"myip": "203.0.113.9"})

    assert response.status_code == 500
    assert store.list_records() == []
    events = store.list_update_events()
    assert events[0]["status"] == "dns_failed"


def test_dns_publish_success_updates_record(tmp_path: Path, monkeypatch) -> None:
    published = []
    monkeypatch.setattr(ddns_service, "publish_dns", lambda result, settings: published.append(result))
    database_path = tmp_path / "ddns.sqlite3"
    store = DdnsStore(database_path)
    account = store.create_account("home.example.net", "alice")
    app = make_app(DdnsSettings(database_path=database_path, admin_password="admin"))
    client = TestClient(app)

    response = client.get(f"/u/{account['update_slug']}", params={"myip": "203.0.113.9"})

    assert response.status_code == 200
    assert response.text == "good 203.0.113.9"
    assert len(published) == 1
    assert store.list_records()[0]["ipv4"] == "203.0.113.9"


def test_generated_account_cannot_update_other_hostname(tmp_path: Path) -> None:
    database_path = tmp_path / "ddns.sqlite3"
    store = DdnsStore(database_path)
    account = store.create_account("home.example.net", "alice")
    app = make_app(DdnsSettings(database_path=database_path, admin_password="admin"))
    client = TestClient(app)

    response = client.get(
        "/nic/update",
        params={
            "hostname": "other.example.net",
            "myip": "203.0.113.9",
            "username": account["username"],
            "password": account["password"],
        },
    )

    assert response.status_code == 401


def test_admin_page_shows_operator_views_without_create_form(tmp_path: Path) -> None:
    database_path = tmp_path / "ddns.sqlite3"
    store = DdnsStore(database_path)
    store.create_domain_challenge("example.net")
    app = make_app(DdnsSettings(database_path=database_path, admin_password="admin"))
    client = TestClient(app)

    response = client.get("/admin", auth=("admin", "admin"))

    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"
    assert "Operator console" in response.text
    assert "Generate credentials" not in response.text
    assert 'action="/admin/accounts"' not in response.text
    assert "Scheduled cleanup" in response.text
    assert "Active credentials" in response.text
    assert "Domain claims" in response.text
    assert "Recent events" in response.text
    assert "example.net" in response.text


def test_admin_posts_require_csrf(tmp_path: Path) -> None:
    app = make_app(DdnsSettings(database_path=tmp_path / "ddns.sqlite3", admin_password="admin"))
    client = TestClient(app)

    response = client.post(
        "/admin/cleanup",
        auth=("admin", "admin"),
        data={},
    )

    assert response.status_code == 403


def test_admin_password_query_string_is_rejected(tmp_path: Path) -> None:
    app = make_app(DdnsSettings(database_path=tmp_path / "ddns.sqlite3", admin_password="admin"))
    client = TestClient(app)

    response = client.get("/admin", params={"password": "admin"})

    assert response.status_code == 401


def test_admin_routes_are_rate_limited(tmp_path: Path) -> None:
    app = make_app(
        DdnsSettings(
            database_path=tmp_path / "ddns.sqlite3",
            admin_password="admin",
            admin_rate_limit_per_minute=1,
        )
    )
    client = TestClient(app)

    first = client.get("/admin", auth=("admin", "wrong"))
    second = client.get("/admin", auth=("admin", "wrong"))

    assert first.status_code == 401
    assert second.status_code == 429


def test_bearer_link_routes_share_rate_limit_bucket(tmp_path: Path) -> None:
    app = make_app(
        DdnsSettings(
            database_path=tmp_path / "ddns.sqlite3",
            admin_password="admin",
            rate_limit_per_minute=1,
        )
    )
    client = TestClient(app)

    first = client.get("/m/not-a-real-token")
    second = client.get("/m/another-token")

    assert first.status_code == 404
    assert second.status_code == 429


def test_admin_can_rotate_links_and_password(tmp_path: Path) -> None:
    settings = DdnsSettings(
        database_path=tmp_path / "ddns.sqlite3",
        admin_password="admin",
        public_base_url="http://ddns.example.net",
    )
    store = DdnsStore(settings.database_path)
    account = store.create_account("home.example.net", "router")
    app = make_app(settings)
    client = TestClient(app)
    csrf = admin_csrf_token(settings)

    update = client.post(
        "/admin/accounts/rotate",
        auth=("admin", "admin"),
        data={"csrf": csrf, "hostname": "home.example.net", "action": "update"},
    )
    assert update.status_code == 200
    assert "Update URL rotated" in update.text
    assert client.get(f"/u/{account['update_slug']}", params={"myip": "203.0.113.9"}).status_code == 404

    management = client.post(
        "/admin/accounts/rotate",
        auth=("admin", "admin"),
        data={"csrf": csrf, "hostname": "home.example.net", "action": "management"},
    )
    assert management.status_code == 200
    assert "Private status page rotated" in management.text
    assert "/m/" in management.text

    password = client.post(
        "/admin/accounts/rotate",
        auth=("admin", "admin"),
        data={"csrf": csrf, "hostname": "home.example.net", "action": "password"},
    )
    assert password.status_code == 200
    assert "Router password rotated" in password.text
    assert "Kennwort:" in password.text


def test_self_service_managed_hostname_generates_random_account(tmp_path: Path) -> None:
    app = make_app(
        DdnsSettings(
            database_path=tmp_path / "ddns.sqlite3",
            admin_password="admin",
            hostname_suffix="ddns.example.net",
            public_base_url="http://ddns.example.net",
        )
    )
    client = TestClient(app)

    response = client.post("/accounts", data={"mode": "managed", "username": "alice"})

    assert response.status_code == 200
    assert "Update-URL:" in response.text
    assert ".ddns.example.net" in response.text
    assert "/u/" in response.text
    assert "/m/" in response.text


def test_magic_hostname_without_login_generates_update_and_management_links(tmp_path: Path) -> None:
    app = make_app(
        DdnsSettings(
            database_path=tmp_path / "ddns.sqlite3",
            admin_password="admin",
            hostname_suffix="ddns.example.net",
            public_base_url="http://ddns.example.net",
        )
    )
    client = TestClient(app)

    response = client.post("/magic", data={"username": "alice"})

    assert response.status_code == 200
    assert "Update-URL:" in response.text
    assert "Private status page:" in response.text
    assert ".ddns.example.net" in response.text


def test_magic_management_link_can_delete_hostname(tmp_path: Path) -> None:
    database_path = tmp_path / "ddns.sqlite3"
    store = DdnsStore(database_path)
    account = store.create_account("home.ddns.example.net", "home")
    app = make_app(DdnsSettings(database_path=database_path, admin_password="admin"))
    client = TestClient(app)

    management = client.get(f"/m/{account['management_slug']}")
    assert management.status_code == 200
    assert "home.ddns.example.net" in management.text
    assert "Router updates" in management.text

    deleted = client.post(f"/m/{account['management_slug']}/delete")
    assert deleted.status_code == 200

    update = client.get(f"/u/{account['update_slug']}", params={"myip": "203.0.113.9"})
    assert update.status_code == 404


def test_management_page_shows_ip_history(tmp_path: Path) -> None:
    database_path = tmp_path / "ddns.sqlite3"
    store = DdnsStore(database_path)
    account = store.create_account("home.ddns.example.net", "router")
    store.log_update_event("home.ddns.example.net", "203.0.113.9", None, "updated", "ok", "198.51.100.1")
    store.log_update_event("home.ddns.example.net", "203.0.113.10", None, "updated", "ok", "198.51.100.1")
    app = make_app(DdnsSettings(database_path=database_path, admin_password="admin"))
    client = TestClient(app)

    response = client.get(f"/m/{account['management_slug']}")

    assert response.status_code == 200
    assert "Router updates" in response.text
    assert "203.0.113.9" in response.text
    assert "203.0.113.10" in response.text


def test_custom_hostname_requires_verified_parent_domain(tmp_path: Path) -> None:
    app = make_app(DdnsSettings(database_path=tmp_path / "ddns.sqlite3", admin_password="admin"))
    client = TestClient(app)

    response = client.post("/accounts", data={"mode": "custom", "hostname": "home.example.net"})

    assert response.status_code == 403


def test_custom_hostname_after_dns_verification(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(ddns_service, "dns_txt_contains", lambda name, expected: True)
    app = make_app(
        DdnsSettings(
            database_path=tmp_path / "ddns.sqlite3",
            admin_password="admin",
            public_base_url="http://ddns.example.net",
        )
    )
    client = TestClient(app)

    store = DdnsStore(tmp_path / "ddns.sqlite3")
    challenge_data = store.create_domain_challenge("example.net")
    verify = client.post(
        "/verify-domain",
        data={"domain": "example.net", "claim_secret": challenge_data["claim_secret"]},
    )
    assert verify.status_code == 200

    response = client.post(
        "/accounts",
        data={"mode": "custom", "hostname": "home.example.net", "claim_secret": challenge_data["claim_secret"]},
    )

    assert response.status_code == 200
    assert "home.example.net" in response.text
    assert "Update-URL:" in response.text


def test_custom_domain_flow_works_without_login(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(ddns_service, "dns_txt_contains", lambda name, expected: True)
    app = make_app(
        DdnsSettings(
            database_path=tmp_path / "ddns.sqlite3",
            admin_password="admin",
            public_base_url="http://ddns.example.net",
        )
    )
    client = TestClient(app)

    challenge = client.post("/request-domain", data={"domain": "example.net"})
    assert challenge.status_code == 200
    assert "Private claim link" in challenge.text
    assert "/d/" in challenge.text

    claim_secret = re.search(r"/d/([A-Za-z0-9_-]+)", challenge.text).group(1)
    claim_page = client.get(f"/d/{claim_secret}")
    assert claim_page.status_code == 200
    assert "TXT value" in claim_page.text

    verify = client.post("/verify-domain", data={"domain": "example.net", "claim_secret": claim_secret})
    assert verify.status_code == 200
    assert "Create credentials" in verify.text

    created = client.post(
        "/accounts",
        data={"mode": "custom", "hostname": "home.example.net", "claim_secret": claim_secret},
    )
    assert created.status_code == 200
    assert "home.example.net" in created.text
    assert "Update-URL:" in created.text


def test_api_docs_include_versioned_ddns_api(tmp_path: Path) -> None:
    app = make_app(DdnsSettings(database_path=tmp_path / "ddns.sqlite3", admin_password="admin"))
    client = TestClient(app)

    docs = client.get("/docs")
    redoc = client.get("/redoc")
    schema = client.get("/openapi.json").json()

    assert docs.status_code == 200
    assert redoc.status_code == 200
    assert "unsafe-inline" in docs.headers["content-security-policy"]
    assert "/api/v1/hostnames/magic" in schema["paths"]
    assert "/api/v1/updates/{update_slug}" in schema["paths"]
    assert "/admin" not in schema["paths"]
    assert "/records" not in schema["paths"]
    assert "/events" not in schema["paths"]
    assert any(tag["name"] == "hostnames" for tag in schema["tags"])
    assert all(tag["name"] != "admin" for tag in schema["tags"])


def test_application_pages_use_stricter_script_csp(tmp_path: Path) -> None:
    app = make_app(DdnsSettings(database_path=tmp_path / "ddns.sqlite3", admin_password="admin"))
    client = TestClient(app)

    response = client.get("/")

    assert response.status_code == 200
    assert '<script src="/app.js" defer></script>' in response.text
    assert "script-src 'self'" in response.headers["content-security-policy"]
    assert "script-src 'self' 'unsafe-inline'" not in response.headers["content-security-policy"]
    assert client.get("/app.js").status_code == 200


def test_trusted_host_middleware_rejects_unlisted_host(tmp_path: Path) -> None:
    app = make_app(
        DdnsSettings(
            database_path=tmp_path / "ddns.sqlite3",
            admin_password="admin",
            public_base_url="http://ddns.example.net",
            trusted_hosts={"ddns.example.net"},
        )
    )
    client = TestClient(app)

    response = client.get("/", headers={"host": "evil.example.net"})

    assert response.status_code == 400


def test_api_magic_hostname_lifecycle(tmp_path: Path) -> None:
    app = make_app(
        DdnsSettings(
            database_path=tmp_path / "ddns.sqlite3",
            admin_password="admin",
            hostname_suffix="ddns.example.net",
            public_base_url="http://ddns.example.net",
        )
    )
    client = TestClient(app)

    created = client.post("/api/v1/hostnames/magic", json={"username": "router"})
    assert created.status_code == 201
    assert created.headers["cache-control"] == "no-store"
    body = created.json()
    assert body["hostname"].endswith(".ddns.example.net")
    assert body["update_url"].startswith("http://ddns.example.net/u/")
    assert body["management_url"].startswith("http://ddns.example.net/m/")

    management_slug = body["management_url"].rsplit("/", 1)[1]
    managed = client.get(f"/api/v1/management/{management_slug}")
    assert managed.status_code == 200
    assert managed.json()["hostname"] == body["hostname"]

    deleted = client.delete(f"/api/v1/management/{management_slug}")
    assert deleted.status_code == 204
    assert client.get(f"/api/v1/management/{management_slug}").status_code == 404


def test_api_update_publishes_before_recording_ip(tmp_path: Path, monkeypatch) -> None:
    published = []
    monkeypatch.setattr(ddns_service, "publish_dns", lambda result, settings: published.append(result))
    database_path = tmp_path / "ddns.sqlite3"
    store = DdnsStore(database_path)
    account = store.create_account("home.ddns.example.net", "router")
    app = make_app(DdnsSettings(database_path=database_path, admin_password="admin"))
    client = TestClient(app)

    response = client.get(f"/api/v1/updates/{account['update_slug']}", params={"myip": "203.0.113.11"})

    assert response.status_code == 200
    assert response.json() == {"status": "good", "hostname": "home.ddns.example.net", "ip": "203.0.113.11"}
    assert len(published) == 1
    assert store.list_records()[0]["ipv4"] == "203.0.113.11"


def test_api_dns_publish_failure_keeps_record_unchanged(tmp_path: Path, monkeypatch) -> None:
    def fail_publish(result, settings):
        raise RuntimeError("dns down")

    monkeypatch.setattr(ddns_service, "publish_dns", fail_publish)
    database_path = tmp_path / "ddns.sqlite3"
    store = DdnsStore(database_path)
    account = store.create_account("home.ddns.example.net", "router")
    app = make_app(DdnsSettings(database_path=database_path, admin_password="admin"))
    client = TestClient(app)

    response = client.get(f"/api/v1/updates/{account['update_slug']}", params={"myip": "203.0.113.11"})

    assert response.status_code == 500
    assert store.list_records() == []
    assert store.list_update_events()[0]["status"] == "dns_failed"


def test_api_custom_hostname_requires_verified_domain(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(ddns_service, "dns_txt_contains", lambda name, expected: True)
    app = make_app(DdnsSettings(database_path=tmp_path / "ddns.sqlite3", admin_password="admin"))
    client = TestClient(app)

    challenge = client.post("/api/v1/domains/challenges", json={"domain": "example.net"})
    assert challenge.status_code == 201
    challenge_body = challenge.json()

    verified = client.post(
        "/api/v1/domains/verify",
        json={"domain": "example.net", "claim_secret": challenge_body["claim_secret"]},
    )
    assert verified.status_code == 200
    assert verified.json()["verified"] is True

    hostname = client.post(
        "/api/v1/hostnames/custom",
        json={
            "hostname": "home.example.net",
            "claim_secret": challenge_body["claim_secret"],
            "username": "router",
        },
    )

    assert hostname.status_code == 201
    assert hostname.json()["hostname"] == "home.example.net"


def test_api_creation_is_rate_limited(tmp_path: Path) -> None:
    app = make_app(
        DdnsSettings(
            database_path=tmp_path / "ddns.sqlite3",
            admin_password="admin",
            hostname_suffix="ddns.example.net",
            rate_limit_per_minute=1,
        )
    )
    client = TestClient(app)

    first = client.post("/api/v1/hostnames/magic", json={"username": "router"})
    second = client.post("/api/v1/hostnames/magic", json={"username": "router"})

    assert first.status_code == 201
    assert second.status_code == 429


def test_secret_html_responses_are_not_cached(tmp_path: Path) -> None:
    app = make_app(
        DdnsSettings(
            database_path=tmp_path / "ddns.sqlite3",
            admin_password="admin",
            hostname_suffix="ddns.example.net",
        )
    )
    client = TestClient(app)

    created = client.post("/magic", data={"username": "router"})

    assert created.status_code == 200
    assert created.headers["cache-control"] == "no-store"
    assert created.headers["pragma"] == "no-cache"


def test_oversized_request_body_is_rejected(tmp_path: Path) -> None:
    app = make_app(
        DdnsSettings(
            database_path=tmp_path / "ddns.sqlite3",
            admin_password="admin",
            hostname_suffix="ddns.example.net",
            max_request_body_bytes=1024,
        )
    )
    client = TestClient(app)

    response = client.post("/magic", data={"username": "x" * 2000})

    assert response.status_code == 413


def test_untrusted_forwarded_for_does_not_bypass_rate_limit(tmp_path: Path) -> None:
    app = make_app(
        DdnsSettings(
            database_path=tmp_path / "ddns.sqlite3",
            admin_password="admin",
            hostname_suffix="ddns.example.net",
            rate_limit_per_minute=1,
        )
    )
    client = TestClient(app)

    first = client.post("/magic", data={"username": "alice"}, headers={"x-forwarded-for": "198.51.100.10"})
    second = client.post("/magic", data={"username": "bob"}, headers={"x-forwarded-for": "198.51.100.11"})

    assert first.status_code == 200
    assert second.status_code == 429


def test_omitted_ip_family_is_preserved(tmp_path: Path, monkeypatch) -> None:
    published = []
    monkeypatch.setattr(ddns_service, "publish_dns", lambda result, settings: published.append(result))
    database_path = tmp_path / "ddns.sqlite3"
    store = DdnsStore(database_path)
    account = store.create_account("home.example.net", "alice")
    store.upsert("home.example.net", "203.0.113.8", "2001:db8::8")
    app = make_app(DdnsSettings(database_path=database_path, admin_password="admin"))
    client = TestClient(app)

    response = client.get(f"/u/{account['update_slug']}", params={"myip": "203.0.113.9"})

    assert response.status_code == 200
    record = store.list_records()[0]
    assert record["ipv4"] == "203.0.113.9"
    assert record["ipv6"] == "2001:db8::8"
    assert published[0].update_ipv4 is True
    assert published[0].update_ipv6 is False


def test_verified_domain_challenge_cannot_be_overwritten(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(ddns_service, "dns_txt_contains", lambda name, expected: True)
    app = make_app(DdnsSettings(database_path=tmp_path / "ddns.sqlite3", admin_password="admin"))
    client = TestClient(app)

    challenge = client.post("/api/v1/domains/challenges", json={"domain": "example.net"}).json()
    verified = client.post(
        "/api/v1/domains/verify",
        json={"domain": "example.net", "claim_secret": challenge["claim_secret"]},
    )
    overwrite = client.post("/api/v1/domains/challenges", json={"domain": "example.net"})

    assert verified.status_code == 200
    assert overwrite.status_code == 409


def test_custom_hostname_must_be_inside_publishable_dns_zone(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(ddns_service, "dns_txt_contains", lambda name, expected: True)
    app = make_app(
        DdnsSettings(
            database_path=tmp_path / "ddns.sqlite3",
            admin_password="admin",
            dns_provider="cloudflare",
            cloudflare_api_token="token",
            cloudflare_zone_id="zone",
            dns_zones={"ddns.example.net"},
        )
    )
    client = TestClient(app)

    challenge = client.post("/api/v1/domains/challenges", json={"domain": "example.net"}).json()
    client.post(
        "/api/v1/domains/verify",
        json={"domain": "example.net", "claim_secret": challenge["claim_secret"]},
    )
    hostname = client.post(
        "/api/v1/hostnames/custom",
        json={"hostname": "home.example.net", "claim_secret": challenge["claim_secret"]},
    )

    assert hostname.status_code == 403
    assert hostname.json()["detail"] == "hostname is outside configured DNS publishing zones"


def test_require_dns_provider_fails_startup_without_backend(tmp_path: Path) -> None:
    try:
        make_app(
            DdnsSettings(
                database_path=tmp_path / "ddns.sqlite3",
                admin_password="admin",
                require_dns_provider=True,
            )
        )
    except RuntimeError as exc:
        assert "no DNS backend" in str(exc)
    else:
        raise AssertionError("expected startup failure")


def test_launch_mode_requires_strong_admin_password(tmp_path: Path) -> None:
    try:
        make_app(
            DdnsSettings(
                database_path=tmp_path / "ddns.sqlite3",
                admin_password="admin",
                public_base_url="http://ddns.example.net",
                hostname_suffix="ddns.example.net",
                dns_provider="cloudflare",
                cloudflare_api_token="token",
                cloudflare_zone_id="zone",
                require_dns_provider=True,
            )
        )
    except RuntimeError as exc:
        assert "DDNS_ADMIN_PASSWORD" in str(exc)
    else:
        raise AssertionError("expected startup failure")


def test_background_cleanup_removes_abandoned_setup_flows(tmp_path: Path) -> None:
    database_path = tmp_path / "ddns.sqlite3"
    app = make_app(
        DdnsSettings(
            database_path=database_path,
            admin_password="admin",
            cleanup_challenge_hours=1,
            cleanup_unused_account_hours=1,
            cleanup_interval_seconds=1,
        )
    )
    store = DdnsStore(database_path)

    with TestClient(app):
        abandoned_claim = store.create_domain_challenge("abandoned.example.net")
        verified_claim = store.create_domain_challenge("verified.example.net")
        abandoned_account = store.create_account("abandoned.ddns.example.net", "router")
        active_account = store.create_account("active.ddns.example.net", "router")
        store.upsert("active.ddns.example.net", "203.0.113.10", None)

        old = "2000-01-01T00:00:00+00:00"
        with store.connect() as conn:
            conn.execute("UPDATE domain_challenges SET created_at = ? WHERE domain = ?", (old, abandoned_claim["domain"]))
            conn.execute(
                "UPDATE domain_challenges SET created_at = ?, verified_at = ? WHERE domain = ?",
                (old, old, verified_claim["domain"]),
            )
            conn.execute("UPDATE accounts SET created_at = ? WHERE hostname = ?", (old, abandoned_account["hostname"]))
            conn.execute("UPDATE accounts SET created_at = ? WHERE hostname = ?", (old, active_account["hostname"]))

        time.sleep(1.3)

    assert store.get_domain_challenge("abandoned.example.net") is None
    assert store.get_domain_challenge("verified.example.net") is not None
    assert store.get_account_by_slug(abandoned_account["update_slug"]) is None
    assert store.get_account_by_slug(active_account["update_slug"]) is not None

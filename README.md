# router-dyndns

A small self-hosted DynDNS service for FRITZ!Box and compatible routers.

It gives users FRITZ!Box-ready DynDNS settings without requiring a full account for provider-owned hostnames. For custom domains, users verify domain ownership with a DNS TXT challenge before creating hostnames.

## Features

- FastAPI app with `/docs`, `/redoc`, and `/openapi.json`.
- Anonymous magic URLs for provider-owned hostnames.
- Optional user sessions for custom-domain verification and hostname quotas.
- FRITZ!Box-compatible update URLs.
- SQLite persistence with WAL mode.
- SQLite-backed rate limiting for public creation and update endpoints.
- Cloudflare DNS publishing.
- RFC 2136 DNS publishing.
- DNS publish-before-store update behavior.
- Per-host update locking inside one server process.
- Custom-domain TXT verification.
- Trusted proxy configuration for `X-Forwarded-For`.
- Docker and Caddy examples.

## Install

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

Run quality checks:

```bash
ruff check router_dyndns tests
pytest
```

## Run Locally

```bash
export DDNS_ADMIN_PASSWORD='long-random-admin-password'
export DDNS_SESSION_SECRET='another-long-random-secret'
export DDNS_PUBLIC_BASE_URL='https://ddns.example.net'
export DDNS_HOSTNAME_SUFFIX='ddns.example.net'
export DDNS_DATABASE='./ddns.sqlite3'
export DDNS_DNS_PROVIDER='cloudflare'
export DDNS_DNS_ZONES='ddns.example.net'
export DDNS_REQUIRE_DNS_PROVIDER=1
export DDNS_CLOUDFLARE_API_TOKEN='cloudflare-api-token'
export DDNS_CLOUDFLARE_ZONE_ID='cloudflare-zone-id'
export DDNS_TRUSTED_PROXY_IPS='127.0.0.1,::1'

router-dyndns serve --host 0.0.0.0 --port 8080
```

Open:

- Customer UI: `https://ddns.example.net/`
- Admin UI: `https://ddns.example.net/admin`
- Swagger UI: `https://ddns.example.net/docs`
- ReDoc: `https://ddns.example.net/redoc`

Admin auth uses HTTP Basic auth. Use any username and `DDNS_ADMIN_PASSWORD` as the password.

## FRITZ!Box Setup

Users receive these fields:

- `Update-URL`
- `Domainnamen`
- `Benutzername`
- `Kennwort`

The generated update URL uses FRITZ!Box placeholders:

```text
/u/<random-update-slug>?myip=<ipaddr>&myipv6=<ip6addr>
```

The compatibility endpoint is also available:

```text
/nic/update?hostname=<domain>&myip=<ipaddr>&myipv6=<ip6addr>&username=<username>&password=<pass>
```

The `/u/<slug>` endpoint is safer for public service use because the user cannot alter the hostname in the router request.

## HTTP API

The API is versioned under `/api/v1`.

Core endpoints:

- `POST /api/v1/hostnames/magic`: create a provider-owned random hostname.
- `GET /api/v1/management/{management_slug}`: inspect a hostname by private management link.
- `DELETE /api/v1/management/{management_slug}`: delete a hostname and DNS records.
- `POST /api/v1/domains/challenges`: create a TXT challenge. Requires login.
- `POST /api/v1/domains/verify`: verify a TXT challenge. Requires login.
- `POST /api/v1/hostnames/custom`: create a custom hostname below a verified and publishable domain. Requires login.
- `GET /api/v1/updates/{update_slug}`: JSON update endpoint.

Example:

```bash
curl -sS https://ddns.example.net/api/v1/hostnames/magic \
  -H 'content-type: application/json' \
  -d '{"username":"home-router"}'
```

## DNS Publishing

For public service use, configure a real DNS backend and set:

```bash
export DDNS_REQUIRE_DNS_PROVIDER=1
```

Cloudflare:

```bash
export DDNS_DNS_PROVIDER=cloudflare
export DDNS_DNS_ZONES=ddns.example.net
export DDNS_CLOUDFLARE_API_TOKEN='cloudflare-api-token'
export DDNS_CLOUDFLARE_ZONE_ID='cloudflare-zone-id'
export DDNS_TTL=60
```

RFC 2136:

```bash
export DDNS_DNS_PROVIDER=rfc2136
export DDNS_DNS_ZONES=ddns.example.net
export DDNS_RFC2136_SERVER=127.0.0.1
export DDNS_RFC2136_ZONE=ddns.example.net
export DDNS_RFC2136_KEY_NAME=ddns-key
export DDNS_RFC2136_KEY_SECRET='base64-tsig-secret'
export DDNS_TTL=60
```

`DDNS_DNS_ZONES` defines which DNS zones this service may publish. A user proving TXT control of a domain is not enough; the hostname must also be inside a zone your DNS backend can update.

## Docker

```bash
docker compose up -d --build
```

Copy `.env.example` to `.env` and set real secrets first.

## Operations

- Run behind HTTPS.
- Use long random values for `DDNS_ADMIN_PASSWORD` and `DDNS_SESSION_SECRET`.
- Configure `DDNS_TRUSTED_PROXY_IPS` only for reverse proxies that strip user-supplied forwarding headers.
- Back up the SQLite database.
- Run one Uvicorn worker with SQLite. The per-host update lock is process-local.

SQLite backup example:

```bash
sqlite3 /data/ddns.sqlite3 ".backup '/backups/router-dyndns.sqlite3'"
```

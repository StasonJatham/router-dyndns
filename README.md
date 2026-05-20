# router-dyndns

`router-dyndns` is a small self-hosted DynDNS service for FRITZ!Box and compatible routers. It provides FRITZ!Box-ready update URLs, publishes A/AAAA records through Cloudflare or RFC 2136, and keeps the operational footprint simple enough for a small VPS.

## Status

This project is suitable for self-hosting and private/public beta use when a real DNS backend is configured. For a larger free public service, add external abuse controls, monitoring, and a backup/restore process before launch.

## Features

- FastAPI application with Swagger UI, ReDoc, and OpenAPI schema.
- Anonymous provider-owned hostnames using cryptographically random update and management URLs.
- Login-gated custom-domain verification with DNS TXT challenges.
- FRITZ!Box-compatible update endpoint and a JSON API under `/api/v1`.
- SQLite persistence with WAL mode and per-IP rate limiting.
- Cloudflare and RFC 2136 DNS publishing.
- Publish-before-store update behavior, with failed DNS updates logged and rejected.
- Per-host update locking inside one server process.
- Safe trusted-proxy handling for `X-Forwarded-For`.
- Docker Compose and Caddy examples.

## Quick Start

```bash
git clone https://github.com/StasonJatham/router-dyndns.git
cd router-dyndns
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

Run locally:

```bash
export DDNS_ADMIN_PASSWORD='replace-with-a-long-random-value'
export DDNS_SESSION_SECRET='replace-with-a-second-long-random-value'
export DDNS_PUBLIC_BASE_URL='http://localhost:8080'
export DDNS_HOSTNAME_SUFFIX='ddns.example.net'
export DDNS_DATABASE='./ddns.sqlite3'

router-dyndns serve --host 127.0.0.1 --port 8080
```

Open:

- Customer UI: `http://localhost:8080/`
- Admin UI: `http://localhost:8080/admin`
- Swagger UI: `http://localhost:8080/docs`
- ReDoc: `http://localhost:8080/redoc`

Admin auth uses HTTP Basic auth. The username can be any value; the password is `DDNS_ADMIN_PASSWORD`.

## Production Configuration

For an internet-facing service, configure HTTPS at your reverse proxy and require a DNS backend:

```bash
export DDNS_PUBLIC_BASE_URL='https://ddns.example.net'
export DDNS_HOSTNAME_SUFFIX='ddns.example.net'
export DDNS_DATABASE='/data/ddns.sqlite3'
export DDNS_REQUIRE_DNS_PROVIDER=1
export DDNS_DNS_ZONES='ddns.example.net'
export DDNS_TRUSTED_PROXY_IPS='127.0.0.1,::1'
```

Cloudflare:

```bash
export DDNS_DNS_PROVIDER='cloudflare'
export DDNS_CLOUDFLARE_API_TOKEN='replace-with-cloudflare-token'
export DDNS_CLOUDFLARE_ZONE_ID='replace-with-cloudflare-zone-id'
export DDNS_TTL=60
```

RFC 2136:

```bash
export DDNS_DNS_PROVIDER='rfc2136'
export DDNS_RFC2136_SERVER='127.0.0.1'
export DDNS_RFC2136_ZONE='ddns.example.net'
export DDNS_RFC2136_KEY_NAME='ddns-key'
export DDNS_RFC2136_KEY_SECRET='replace-with-tsig-secret'
export DDNS_TTL=60
```

`DDNS_DNS_ZONES` is the allowlist of zones this service may publish. A custom domain must pass TXT verification and the requested hostname must be inside one of these zones.

## FRITZ!Box Setup

Create a hostname in the web UI. The generated page shows the exact values for the FRITZ!Box DynDNS form:

- `Update-URL`
- `Domainnamen`
- `Benutzername`
- `Kennwort`

The generated update URL uses FRITZ!Box placeholders:

```text
/u/<random-update-slug>?myip=<ipaddr>&myipv6=<ip6addr>
```

The legacy compatibility endpoint is also available:

```text
/nic/update?hostname=<domain>&myip=<ipaddr>&myipv6=<ip6addr>&username=<username>&password=<pass>
```

Prefer `/u/<slug>` for managed service use because the router request cannot change the hostname.

## HTTP API

The API is available under `/api/v1`.

| Endpoint | Purpose |
| --- | --- |
| `POST /api/v1/hostnames/magic` | Create an anonymous provider-owned hostname. |
| `GET /api/v1/management/{management_slug}` | Inspect a hostname by private management link. |
| `DELETE /api/v1/management/{management_slug}` | Delete a hostname and its DNS records. |
| `POST /api/v1/domains/challenges` | Create a TXT challenge. Requires login. |
| `POST /api/v1/domains/verify` | Verify a TXT challenge. Requires login. |
| `POST /api/v1/hostnames/custom` | Create a custom hostname below a verified, publishable domain. Requires login. |
| `GET /api/v1/updates/{update_slug}` | JSON update endpoint for routers or automation. |

Example:

```bash
curl -sS https://ddns.example.net/api/v1/hostnames/magic \
  -H 'content-type: application/json' \
  -d '{"username":"home-router"}'
```

## Docker

Copy the example environment file and replace every placeholder:

```bash
cp .env.example .env
docker compose up -d --build
```

`Caddyfile.example` contains a minimal HTTPS reverse proxy example.

## Operations

- Run behind HTTPS.
- Keep `.env` out of git.
- Use long random values for `DDNS_ADMIN_PASSWORD` and `DDNS_SESSION_SECRET`.
- Use a least-privilege DNS API token limited to the managed zone.
- Configure `DDNS_TRUSTED_PROXY_IPS` only for reverse proxies that strip user-supplied forwarding headers.
- Back up `/data/ddns.sqlite3`.
- Run one Uvicorn worker with SQLite. The per-host update lock is process-local.

SQLite backup example:

```bash
sqlite3 /data/ddns.sqlite3 ".backup '/backups/router-dyndns.sqlite3'"
```

## Development

```bash
ruff check router_dyndns tests
pytest
python -m compileall router_dyndns
```

## Security

The repository intentionally contains only placeholders in `.env.example` and documentation. Do not commit a real `.env`, DNS token, TSIG secret, admin password, session secret, database, or router-generated update URL.

If you find a vulnerability, open a private advisory or contact the repository owner before publishing details.

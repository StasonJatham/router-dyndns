# RouterPulse

**Self-hosted DynDNS for FRITZ!Box, OpenWrt, pfSense, OPNsense, UniFi, MikroTik, and any router that can call a custom DDNS update URL.**

RouterPulse is the friendly name for `router-dyndns`: a small FastAPI Dynamic DNS provider you can run on your own VPS. It gives users FRITZ!Box-ready DynDNS credentials, keeps public A/AAAA records updated through Cloudflare or RFC 2136, and supports verified custom domains with DNS TXT ownership checks.

If you want a lightweight DuckDNS / Dynu / No-IP style service that you control yourself, RouterPulse is built for that use case.

![RouterPulse self-hosted DynDNS home screen](docs/screenshots/home.png)

## Why RouterPulse?

- **Self-hosted Dynamic DNS provider** for home labs, small ISPs, communities, and private infrastructure.
- **FRITZ!Box compatible**: copy the generated `Update-URL`, `Domainnamen`, `Benutzername`, and `Kennwort` straight into the German FRITZ!Box DynDNS form.
- **No registration required**: provider hostnames and custom-domain setup both use private magic links.
- **Custom domain support**: users enter a domain, save the private claim link, add a DNS TXT record, then press a button to verify ownership before credentials are issued.
- **Real DNS publishing** through **Cloudflare** or **RFC 2136** with A and AAAA support.
- **Small-server friendly**: FastAPI, SQLite WAL, simple Docker deployment, and no heavy background platform.
- **API first**: OpenAPI, Swagger UI, ReDoc, and JSON endpoints under `/api/v1`.

## Screenshots

### Generate Router Credentials

![Generated FRITZ!Box DynDNS credentials](docs/screenshots/generated-credentials.png)

### Verify a Custom Domain

![DNS TXT verification flow for custom domains](docs/screenshots/domain-verification.png)

## What It Does

RouterPulse lets you host your own managed DynDNS service:

1. A user opens your RouterPulse URL.
2. They generate a random hostname like `a1b2c3d4.ddns.example.net`, or verify their own domain with a TXT record.
3. RouterPulse shows the exact router settings for the DynDNS form.
4. The router periodically calls the update URL with its current public IPv4/IPv6 address.
5. RouterPulse publishes the matching DNS records through your configured DNS backend.

That means users always have a current hostname for VPN, remote access, self-hosted apps, home servers, NAS devices, and lab networks.

## Best Use Cases

- Self-hosted DynDNS for FRITZ!Box routers.
- Free DDNS service for friends, customers, a community, or a home lab.
- Dynamic DNS for IPv4 and IPv6 home internet connections.
- Custom domain DDNS with DNS TXT verification.
- Lightweight Cloudflare DDNS provider with a web UI.
- RFC 2136 / TSIG DynDNS frontend for BIND, Knot, PowerDNS, or compatible DNS servers.

## Feature Overview

| Area | Support |
| --- | --- |
| Router update URLs | FRITZ!Box custom provider URL, `/u/<slug>`, and `/nic/update` compatibility |
| DNS records | A and AAAA |
| DNS providers | Cloudflare API and RFC 2136 dynamic DNS |
| Custom domains | TXT challenge verification before hostname creation |
| Persistence | SQLite with WAL mode |
| API | FastAPI, OpenAPI, Swagger UI, ReDoc |
| Auth model | Private magic links for hostnames and custom-domain claims; optional account workspace for dashboards |
| Operations | Rate limiting, update logs, cleanup jobs, Docker, Caddy example |

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

- Web UI: `http://localhost:8080/`
- Admin UI: `http://localhost:8080/admin`
- Swagger UI: `http://localhost:8080/docs`
- ReDoc: `http://localhost:8080/redoc`

Admin auth uses HTTP Basic auth. The username can be any value; the password is `DDNS_ADMIN_PASSWORD`.

## Production Setup

For an internet-facing DynDNS service, run behind HTTPS and require a real DNS backend:

```bash
export DDNS_PUBLIC_BASE_URL='https://ddns.example.net'
export DDNS_HOSTNAME_SUFFIX='ddns.example.net'
export DDNS_DATABASE='/data/ddns.sqlite3'
export DDNS_REQUIRE_DNS_PROVIDER=1
export DDNS_DNS_ZONES='ddns.example.net'
export DDNS_TRUSTED_PROXY_IPS='127.0.0.1,::1'
```

### Cloudflare DNS Backend

```bash
export DDNS_DNS_PROVIDER='cloudflare'
export DDNS_CLOUDFLARE_API_TOKEN='replace-with-cloudflare-token'
export DDNS_CLOUDFLARE_ZONE_ID='replace-with-cloudflare-zone-id'
export DDNS_TTL=60
```

Use a least-privilege Cloudflare API token limited to the zone RouterPulse should update.

### RFC 2136 DNS Backend

```bash
export DDNS_DNS_PROVIDER='rfc2136'
export DDNS_RFC2136_SERVER='127.0.0.1'
export DDNS_RFC2136_ZONE='ddns.example.net'
export DDNS_RFC2136_KEY_NAME='ddns-key'
export DDNS_RFC2136_KEY_SECRET='replace-with-tsig-secret'
export DDNS_TTL=60
```

`DDNS_DNS_ZONES` is the allowlist of DNS zones this service may publish. A custom hostname must be inside one of these zones.

## FRITZ!Box DynDNS Setup

Create a hostname in the web UI. RouterPulse shows the exact values for:

- `Update-URL`
- `Domainnamen`
- `Benutzername`
- `Kennwort`

The generated FRITZ!Box URL uses the native placeholders:

```text
https://ddns.example.net/u/<random-update-slug>?myip=<ipaddr>&myipv6=<ip6addr>
```

The compatibility endpoint is also available:

```text
https://ddns.example.net/nic/update?hostname=<domain>&myip=<ipaddr>&myipv6=<ip6addr>&username=<username>&password=<pass>
```

Prefer `/u/<slug>` for managed service use because the router request cannot change the hostname.

## Custom Domain Flow

Custom domains are intentionally simple:

1. Enter the domain.
2. Save the private claim link.
3. Add the generated TXT record at your DNS provider.
4. Press **I added it, check DNS**.
5. Create router credentials after the TXT record verifies.

RouterPulse stores the domain claim in SQLite and only creates hostnames below verified, publishable zones. The private claim link is the bearer credential for returning later after DNS propagation.

## HTTP API

The JSON API is available under `/api/v1`.

| Endpoint | Purpose |
| --- | --- |
| `POST /api/v1/hostnames/magic` | Create an anonymous provider-owned hostname. |
| `GET /api/v1/management/{management_slug}` | Inspect a hostname by private management link. |
| `DELETE /api/v1/management/{management_slug}` | Delete a hostname and its DNS records. |
| `POST /api/v1/domains/challenges` | Create a TXT challenge and private claim secret. |
| `POST /api/v1/domains/verify` | Verify a TXT challenge with the claim secret. |
| `POST /api/v1/hostnames/custom` | Create a custom hostname below a verified domain with the claim secret. |
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

## Operations Checklist

- Run behind HTTPS.
- Keep `.env` out of git.
- Use long random values for `DDNS_ADMIN_PASSWORD` and `DDNS_SESSION_SECRET`.
- Use a least-privilege DNS API token or TSIG key.
- Configure `DDNS_TRUSTED_PROXY_IPS` only for reverse proxies that strip user-supplied forwarding headers.
- Back up `/data/ddns.sqlite3`.
- Run one Uvicorn worker with SQLite. The per-host update lock is process-local.

SQLite backup example:

```bash
sqlite3 /data/ddns.sqlite3 ".backup '/backups/routerpulse.sqlite3'"
```

## Project Status

RouterPulse is suitable for self-hosting and private/public beta use when a real DNS backend is configured. For a larger public free DynDNS provider, add external abuse controls, monitoring, alerting, and a tested backup/restore process before launch.

## Development

```bash
ruff check router_dyndns tests
pytest
python -m compileall router_dyndns
```

## SEO Keywords

Self-hosted DynDNS, self hosted DDNS, Dynamic DNS server, FRITZ!Box DynDNS, FRITZ Box DDNS, Cloudflare DDNS, RFC 2136 DDNS, custom DynDNS provider, home lab DDNS, router dynamic DNS, IPv6 DynDNS, open source DynDNS provider, DuckDNS alternative, No-IP alternative, Dynu alternative.

## Security

The repository intentionally contains only placeholders in `.env.example` and documentation. Do not commit a real `.env`, DNS token, TSIG secret, admin password, session secret, database, or router-generated update URL.

If you find a vulnerability, open a private advisory or contact the repository owner before publishing details.

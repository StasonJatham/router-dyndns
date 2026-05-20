from __future__ import annotations

import argparse

from .ddns import DdnsSettings, make_app


def main() -> None:
    parser = argparse.ArgumentParser(prog="karldns")
    subparsers = parser.add_subparsers(dest="command", required=True)

    render_url = subparsers.add_parser("render-fritz-url", help="Render a FRITZ!Box custom DynDNS update URL.")
    render_url.add_argument("--base-url", required=True, help="Public base URL of this DDNS service.")
    render_url.add_argument("--host", required=True, help="DNS hostname configured in FRITZ!Box.")
    render_url.add_argument("--include-ipv6", action="store_true")

    serve = subparsers.add_parser("serve", help="Run the DDNS HTTP service.")
    serve.add_argument("--host", default="0.0.0.0")
    serve.add_argument("--port", type=int, default=8080)

    args = parser.parse_args()
    if args.command == "render-fritz-url":
        print(_render_fritz_url(args.base_url, args.host, args.include_ipv6))
    elif args.command == "serve":
        import uvicorn

        settings = DdnsSettings.from_env()
        if not settings.admin_password:
            raise SystemExit("DDNS_ADMIN_PASSWORD must be set.")
        uvicorn.run(make_app(settings), host=args.host, port=args.port)


def _render_fritz_url(base_url: str, host: str, include_ipv6: bool) -> str:
    base = base_url.rstrip("/")
    url = f"{base}/nic/update?hostname=<domain>&myip=<ipaddr>&username=<username>&password=<pass>"
    if include_ipv6:
        url += "&myipv6=<ip6addr>"
    return url.replace("<domain>", host)


if __name__ == "__main__":
    main()


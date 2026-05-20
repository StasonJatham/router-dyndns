import sqlite3

from fastapi import APIRouter, HTTPException, Request, Response, status
from pydantic import BaseModel, Field
from starlette.concurrency import run_in_threadpool

from .ddns_models import DdnsSettings
from .ddns_service import DdnsService, normalize_domain
from .ddns_store import DdnsStore


class ErrorResponse(BaseModel):
    detail: str = Field(examples=["not found"])


class MagicHostnameRequest(BaseModel):
    username: str | None = Field(default=None, max_length=128, examples=["home-router"])


class HostnameCredentials(BaseModel):
    hostname: str
    username: str
    password: str
    update_url: str
    management_url: str


class ManagedRecord(BaseModel):
    hostname: str
    username: str
    update_url: str
    ipv4: str | None = None
    ipv6: str | None = None
    updated_at: str | None = None


class DomainChallengeRequest(BaseModel):
    domain: str = Field(examples=["example.net"])


class DomainChallengeResponse(BaseModel):
    domain: str
    txt_name: str
    txt_value: str
    claim_secret: str


class VerifyDomainRequest(BaseModel):
    domain: str = Field(examples=["example.net"])
    claim_secret: str


class VerifyDomainResponse(BaseModel):
    domain: str
    verified: bool
    message: str
    claim_secret: str


class CustomHostnameRequest(BaseModel):
    hostname: str = Field(examples=["home.example.net"])
    claim_secret: str
    username: str | None = Field(default=None, max_length=128, examples=["home-router"])


class RouterUpdateResponse(BaseModel):
    status: str = Field(examples=["good"])
    hostname: str
    ip: str


def create_api_router(settings: DdnsSettings, store: DdnsStore, service: DdnsService) -> APIRouter:
    router = APIRouter(prefix="/api/v1")

    @router.post(
        "/hostnames/magic",
        response_model=HostnameCredentials,
        status_code=status.HTTP_201_CREATED,
        summary="Generate a provider-owned DynDNS hostname",
        tags=["hostnames"],
        responses={500: {"model": ErrorResponse}},
    )
    async def create_magic_hostname(payload: MagicHostnameRequest) -> HostnameCredentials:
        account = await run_in_threadpool(service.create_managed_account, payload.username)
        return _credentials_response(service, account)

    @router.get(
        "/management/{management_slug}",
        response_model=ManagedRecord,
        summary="Read a hostname by magic management link",
        tags=["management"],
        responses={404: {"model": ErrorResponse}},
    )
    async def read_managed_hostname(management_slug: str) -> ManagedRecord:
        account = await run_in_threadpool(store.get_account_by_management_slug, management_slug)
        if not account or account["disabled"]:
            raise HTTPException(status_code=404, detail="not found")
        return _managed_record(service, account)

    @router.delete(
        "/management/{management_slug}",
        status_code=status.HTTP_204_NO_CONTENT,
        summary="Delete a hostname by magic management link",
        tags=["management"],
        responses={404: {"model": ErrorResponse}, 500: {"model": ErrorResponse}},
    )
    async def delete_managed_hostname(management_slug: str) -> Response:
        account = await run_in_threadpool(store.get_account_by_management_slug, management_slug)
        if not account or account["disabled"]:
            raise HTTPException(status_code=404, detail="not found")
        hostname = str(account["hostname"])
        try:
            await run_in_threadpool(service.delete_account, hostname, "api")
        except Exception as exc:
            raise HTTPException(status_code=500, detail="DNS delete failed; hostname was not deleted") from exc
        return Response(status_code=status.HTTP_204_NO_CONTENT)

    @router.post(
        "/domains/challenges",
        response_model=DomainChallengeResponse,
        status_code=status.HTTP_201_CREATED,
        summary="Create a DNS TXT domain verification challenge",
        tags=["domains"],
        responses={400: {"model": ErrorResponse}},
    )
    async def create_domain_challenge(
        payload: DomainChallengeRequest,
    ) -> DomainChallengeResponse:
        domain = normalize_domain(payload.domain)
        try:
            challenge = await run_in_threadpool(service.create_domain_challenge, domain)
        except sqlite3.IntegrityError as exc:
            raise HTTPException(status_code=409, detail="domain is already verified") from exc
        return DomainChallengeResponse(
            domain=domain,
            txt_name=service.verification_name(domain),
            txt_value=challenge["token"],
            claim_secret=challenge["claim_secret"],
        )

    @router.post(
        "/domains/verify",
        response_model=VerifyDomainResponse,
        summary="Verify a domain TXT challenge",
        tags=["domains"],
        responses={404: {"model": ErrorResponse}},
    )
    async def verify_domain(
        payload: VerifyDomainRequest,
    ) -> VerifyDomainResponse:
        domain = normalize_domain(payload.domain)
        found, challenge = await run_in_threadpool(service.verify_domain, domain, payload.claim_secret)
        if not found:
            return VerifyDomainResponse(
                domain=domain,
                verified=False,
                message="TXT record not found yet",
                claim_secret=payload.claim_secret,
            )
        return VerifyDomainResponse(
            domain=domain,
            verified=True,
            message="domain verified",
            claim_secret=payload.claim_secret,
        )

    @router.post(
        "/hostnames/custom",
        response_model=HostnameCredentials,
        status_code=status.HTTP_201_CREATED,
        summary="Generate credentials for a verified custom hostname",
        tags=["hostnames"],
        responses={400: {"model": ErrorResponse}, 403: {"model": ErrorResponse}, 409: {"model": ErrorResponse}},
    )
    async def create_custom_hostname(
        payload: CustomHostnameRequest,
    ) -> HostnameCredentials:
        account = await run_in_threadpool(
            service.create_custom_account,
            payload.hostname,
            payload.claim_secret,
            payload.username,
        )
        return _credentials_response(service, account)

    @router.get(
        "/updates/{update_slug}",
        response_model=RouterUpdateResponse,
        summary="Router-compatible update endpoint",
        tags=["updates"],
        responses={404: {"model": ErrorResponse}, 500: {"model": ErrorResponse}},
    )
    async def update_hostname(
        update_slug: str,
        request: Request,
        myip: str | None = None,
        ipaddr: str | None = None,
        myipv6: str | None = None,
        ip6addr: str | None = None,
    ) -> RouterUpdateResponse:
        account = await run_in_threadpool(store.get_account_by_slug, update_slug)
        if not account or account["disabled"]:
            raise HTTPException(status_code=404, detail="not found")

        hostname = str(account["hostname"])
        try:
            outcome = await run_in_threadpool(
                service.apply_update,
                request,
                hostname,
                myip,
                ipaddr,
                myipv6,
                ip6addr,
            )
        except Exception as exc:
            raise HTTPException(status_code=500, detail="DNS publish failed") from exc
        result = outcome.result
        return RouterUpdateResponse(status="good" if result.changed else "nochg", hostname=hostname, ip=result.ipv4 or result.ipv6 or "")

    return router


def _credentials_response(service: DdnsService, account: dict[str, str]) -> HostnameCredentials:
    return HostnameCredentials(
        hostname=account["hostname"],
        username=account["username"],
        password=account["password"],
        update_url=service.fritz_update_url(account),
        management_url=service.magic_management_url(account),
    )


def _managed_record(service: DdnsService, account: dict[str, str | int | None]) -> ManagedRecord:
    account_for_url = {"update_slug": str(account["update_slug"])}
    return ManagedRecord(
        hostname=str(account["hostname"]),
        username=str(account["username"]),
        update_url=service.fritz_update_url(account_for_url),
        ipv4=str(account["ipv4"]) if account.get("ipv4") else None,
        ipv6=str(account["ipv6"]) if account.get("ipv6") else None,
        updated_at=str(account["updated_at"]) if account.get("updated_at") else None,
    )

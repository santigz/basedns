import json
import logging
from urllib.parse import quote, unquote

from fastapi import FastAPI, APIRouter, Request, HTTPException, status, Security, Query
from fastapi.responses import HTMLResponse, PlainTextResponse, JSONResponse
from fastapi.security import APIKeyHeader, APIKeyQuery
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from pydantic_settings import BaseSettings, SettingsConfigDict
from typing import Optional

from .dns_manager import (
    ZoneManager,
    BadZoneFile,
    RecordUpdateError,
    InvalidSubdomainError,
    SubdomainUnavailableError,
)

ADMIN_GROUP = "basedns-admin"
APP_PREFIX = "/app"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")
    root_domain: str = "example.com."
    website_url: str = "http://localhost"
    testing_mode: bool = False
    testing_user: str = 'user'
    testing_groups: str = ADMIN_GROUP
    logout_url: str = ""


def encode_logout_url(url: str) -> str:
    """Encode the redirect target in LOGOUT_URL safely for use in a link."""
    url = (url or "").strip()
    if not url:
        return ""
    if "?rd=" in url:
        base, rd = url.split("?rd=", 1)
        return f"{base}?rd={quote(unquote(rd), safe='')}"
    return url


logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.DEBUG)

settings = Settings()
app = FastAPI()
app_router = APIRouter(prefix=APP_PREFIX)
app.mount("/static", StaticFiles(directory="static"), name="static")

templates = Jinja2Templates(directory="templates/")
zonemgr = ZoneManager(settings.root_domain)

# For user tokens
api_key_query = APIKeyQuery(name="api_key", auto_error=False)
api_key_header = APIKeyHeader(name="x-api-key", auto_error=False)



def check_user(request):
    username = request.headers.get('remote-user')
    if not username and settings.testing_mode:
        username = settings.testing_user
    if not username:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid user.")
    return username


def get_user_groups(request: Request) -> list[str]:
    raw_groups = request.headers.get('remote-groups')
    if raw_groups is None and not request.headers.get('remote-user') and settings.testing_mode:
        raw_groups = settings.testing_groups
    if not raw_groups:
        return []
    return [g.strip() for g in raw_groups.split(',') if g.strip()]


def is_admin(request: Request) -> bool:
    return ADMIN_GROUP in get_user_groups(request)


def check_admin(request: Request) -> str:
    username = check_user(request)
    if not is_admin(request):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required.",
        )
    return username


@app.get('/', response_class=HTMLResponse)
async def read_root(request: Request):
    return templates.TemplateResponse(
        request=request,
        name="html/index.html",
        context={"app_prefix": APP_PREFIX},
    )


@app_router.get('', response_class=HTMLResponse)
async def read_app(request: Request):
    username = check_user(request)
    user_zone = zonemgr.get_user_zonefile(username)
    user_origin = zonemgr.user_zone_origin(username)
    user_subdomain = zonemgr.get_user_subdomain(username)
    ctx = {
            "username": username,
            "user_origin": user_origin,
            "user_subdomain": user_subdomain,
            "root_domain": zonemgr.origin,
            "user_zone": user_zone,
            "testing_mode": settings.testing_mode,
            "user_token": zonemgr.get_user_token(username),
            "website_url": settings.website_url,
            "app_prefix": APP_PREFIX,
            "logout_url": encode_logout_url(settings.logout_url),
            "is_admin": is_admin(request),
          }
    return templates.TemplateResponse(request=request, name="html/user.html", context=ctx)


@app_router.get('/headers')
async def read_headers(request: Request):
    check_user(request)
    # TODO: check user belongs to group dns_admin
    headers = dict(request.headers)
    return JSONResponse(content=headers)


@app_router.get('/admin/users')
def admin_list_users(request: Request):
    check_admin(request)
    return {"users": zonemgr.list_users_summary()}


@app_router.get('/admin/users/{username}/zonefile', response_class=PlainTextResponse)
def admin_read_user_zone(request: Request, username: str):
    check_admin(request)
    zone = zonemgr.read_existing_user_zonefile(username)
    if zone is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User zone not found.",
        )
    return zone


@app_router.delete('/admin/users/{username}')
def admin_delete_user(request: Request, username: str):
    admin_username = check_admin(request)
    if username == admin_username:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="You cannot delete your own user.",
        )
    if not zonemgr.delete_user(username):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found.",
        )
    return {"status": "deleted", "username": username}


@app_router.get('/admin/backups')
def admin_list_backups(request: Request):
    check_admin(request)
    return {"backups": zonemgr.list_backups()}



@app_router.get('/zonefile', response_class=PlainTextResponse)
def read_user_zone(request: Request):
    username = check_user(request)
    try:
        zone = zonemgr.get_user_zonefile(username)
        return zone
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app_router.put('/zonefile')
async def set_user_zone(request: Request):
    username = check_user(request)
    try:
        data = await request.body()
        data_str = data.decode("utf-8")
        logger.info(f'Set zone for {username}:\n{data_str}')
        zonemgr.set_user_zonefile(username, data_str)
    except BadZoneFile as e:
        logger.error(f'Bad zone for {username}:\n{str(e)}')
        # logger.error(traceback.print_exc())
        raise HTTPException(status_code=400, detail={'error': 'Bad zone file', 'message': str(e)})
    except Exception as e:
        logger.error(f'Exception setting zone file for {username}:\n{str(e)}')
        # logger.error(traceback.print_exc())
        raise HTTPException(status_code=500, detail={'error': 'Internal error', 'message': str(e)})


@app_router.post('/reset_zonefile', response_class=PlainTextResponse)
def reset_zone(request: Request):
    username = check_user(request)
    try:
        return zonemgr.reset_user_zonefile(username)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app_router.get('/origin/available')
def check_origin_available(
    request: Request,
    subdomain: str = Query(..., description="Candidate subdomain label"),
):
    username = check_user(request)
    try:
        normalized = zonemgr.validate_subdomain(subdomain)
    except InvalidSubdomainError as e:
        return {
            "available": False,
            "valid": False,
            "subdomain": None,
            "origin": None,
            "reason": str(e),
        }
    origin = f"{normalized}.{zonemgr.origin}"
    current_sub = zonemgr.find_user_zones().get(username)
    if current_sub is not None and current_sub.lower() == normalized:
        return {
            "available": False,
            "valid": True,
            "subdomain": normalized,
            "origin": origin,
            "reason": f'"{origin}" is already your current zone origin.',
        }
    if normalized in zonemgr.reserved_subdomains():
        return {
            "available": False,
            "valid": True,
            "subdomain": normalized,
            "origin": origin,
            "reason": f'Subdomain "{normalized}" is reserved and cannot be used.',
        }
    if not zonemgr.is_subdomain_available(normalized, exclude_user=username):
        return {
            "available": False,
            "valid": True,
            "subdomain": normalized,
            "origin": origin,
            "reason": f'Subdomain "{origin}" is already taken.',
        }
    return {
        "available": True,
        "valid": True,
        "subdomain": normalized,
        "origin": origin,
        "reason": None,
    }


@app_router.post('/origin')
async def change_origin(request: Request):
    username = check_user(request)
    raw_body = await request.body()
    body_str = raw_body.decode("utf-8").strip()
    new_subdomain = ""
    try:
        payload = json.loads(body_str) if body_str.startswith("{") else None
    except json.JSONDecodeError:
        payload = None

    if isinstance(payload, dict):
        if not payload.get("acknowledge", False):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={
                    "error": "Acknowledgement required",
                    "message": "You must acknowledge that your existing zone file will be destroyed.",
                },
            )
        new_subdomain = str(payload.get("subdomain") or payload.get("origin") or "")
    else:
        new_subdomain = body_str

    try:
        zone = zonemgr.change_user_origin(username, new_subdomain)
        updated_subdomain = zonemgr.get_user_subdomain(username)
        return {
            "status": "updated",
            "subdomain": updated_subdomain,
            "origin": zonemgr.user_zone_origin(username),
            "zone": zone,
        }
    except InvalidSubdomainError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": "Invalid origin", "message": str(e)},
        )
    except SubdomainUnavailableError as e:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"error": "Origin unavailable", "message": str(e)},
        )
    except Exception as e:
        logger.error(f"Exception changing origin for {username}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"error": "Internal error", "message": str(e)},
        )


def get_api_key(
    api_key_query: str = Security(api_key_query),
    api_key_header: str = Security(api_key_header),
) -> str:
    # From https://joshdimella.com/blog/adding-api-key-auth-to-fast-api
    tokens = zonemgr.load_user_tokens().values()
    if api_key_query in tokens:
        return api_key_query
    if api_key_header in tokens:
        return api_key_header
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or missing API Key",
    )

@app.post("/update/{hostname}")
async def update_dns(
        hostname: str, 
        request: Request,
        api_key: str = Security(get_api_key),
        ip: Optional[str] = Query(None, description="The new IP address for the hostname. If not provided, the IP that originates the request is used."),
        ):
    username = zonemgr.find_user_for_token(api_key)
    if not username:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='Bad token')
    if not ip:
        if 'x-real-ip' in request.headers:
            # If we are behind a reverse proxy
            ip = request.headers['x-real-ip']
        else:
            ip = request.client.host
    try:
        zonemgr.update_a_record(username, hostname, ip)
    except BadZoneFile as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail='Bad domain name.')
    except RecordUpdateError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except Exception as e:
        logger.error(f'Error in dyndns:\n{e}')
        raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail='Something bad happened. Try again later or try resetting your DNS zone.')
    return {'status': 'updated',
            'hostname': hostname,
            'ip': ip}




@app.get('/dyndns_install.sh', response_class=PlainTextResponse)
async def dyndns_install_script(request: Request):
    ctx = {"website_url": settings.website_url}
    return templates.TemplateResponse(request=request, name='dyndns_install.sh.j2', context=ctx)


app.include_router(app_router)

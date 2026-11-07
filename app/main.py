import logging

from fastapi import FastAPI, Request, HTTPException, status, Security, Query
from fastapi.responses import HTMLResponse, PlainTextResponse, JSONResponse
from fastapi.security import APIKeyHeader, APIKeyQuery
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from pydantic_settings import BaseSettings
from typing import Optional

from .dns_manager import ZoneManager, BadZoneFile, RecordUpdateError


class Settings(BaseSettings):
    root_domain: str = "example.com."
    website_url: str = "http://localhost"
    testing_mode: bool = False
    testing_user: str = 'user'


logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.DEBUG)

settings = Settings()
app = FastAPI()
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


@app.get('/', response_class=HTMLResponse)
async def read_root(request: Request):
    username = request.headers.get('remote-user')
    if not username and settings.testing_mode:
        username = settings.testing_user
    if not username:
        ctx = {
                "username": username,
              }
        return templates.TemplateResponse(request=request, name="html/index.html", context=ctx)
    ctx = {
            "username": username,
            "user_origin": zonemgr.user_zone_origin(username),
            "user_zone": zonemgr.get_user_zonefile(username),
            "testing_mode": settings.testing_mode,
            "user_token": zonemgr.get_user_token(username),
            "website_url": settings.website_url,
          }
    return templates.TemplateResponse(request=request, name="html/user.html", context=ctx)


@app.get('/headers')
async def read_headers(request: Request):
    check_user(request)
    # TODO: check user belongs to group dns_admin
    headers = dict(request.headers)
    return JSONResponse(content=headers)



@app.get('/zonefile', response_class=PlainTextResponse)
def read_user_zone(request: Request):
    username = check_user(request)
    try:
        zone = zonemgr.get_user_zonefile(username)
        return zone
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.put('/zonefile')
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


@app.post('/reset_zonefile', response_class=PlainTextResponse)
def reset_zone(request: Request):
    username = check_user(request)
    try:
        return zonemgr.reset_user_zonefile(username)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


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

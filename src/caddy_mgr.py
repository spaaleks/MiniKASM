import json
import logging
import urllib.request
import urllib.error
import base64

logger = logging.getLogger(__name__)

CADDY_ADMIN_URL = "http://localhost:2019"


def _caddy_request(method: str, path: str, data: dict | list | None = None) -> dict | list | None:
    url = f"{CADDY_ADMIN_URL}{path}"
    headers = {"Content-Type": "application/json"}
    body = json.dumps(data).encode() if data is not None else None
    req = urllib.request.Request(url, data=body, headers=headers, method=method)

    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            content = resp.read()
            if content:
                return json.loads(content)
            return {}
    except urllib.error.HTTPError as e:
        if e.code == 404:
            logger.debug(f"Caddy API 404: {path}")
            return None
        logger.error(f"Caddy API error: {e.code} {e.reason} for {method} {path}")
        try:
            error_body = e.read().decode()
            logger.error(f"Caddy error body: {error_body}")
        except:
            pass
        return None
    except urllib.error.URLError as e:
        logger.error(f"Caddy connection error: {e}")
        return None
    except Exception as e:
        logger.error(f"Caddy request error: {e}")
        return None


def register_session_route(
    session_id: str,
    container_ip: str,
    container_port: int,
    session_prefix: str,
    vnc_password: str | None = None,
) -> bool:
    path_prefix = f"{session_prefix}/{session_id}"

    auth_header = None
    if vnc_password:
        creds = f"kasm_user:{vnc_password}"
        auth_header = f"Basic {base64.b64encode(creds.encode()).decode()}"

    session_route = {
        "@id": f"session-{session_id}",
        "match": [{"path": [f"{path_prefix}", f"{path_prefix}/*"]}],
        "handle": [
            {
                "handler": "headers",
                "response": {
                    "add": {
                        "Set-Cookie": [f"kasm_session={session_id}; Path=/; SameSite=Lax"]
                    }
                }
            },
            {
                "handler": "rewrite",
                "strip_path_prefix": path_prefix
            },
            {
                "handler": "reverse_proxy",
                "upstreams": [{"dial": f"{container_ip}:{container_port}"}],
                "transport": {
                    "protocol": "http",
                    "tls": {"insecure_skip_verify": True}
                }
            }
        ]
    }

    if auth_header:
        session_route["handle"][2]["headers"] = {
            "request": {"set": {"Authorization": [auth_header]}}
        }

    result = _caddy_request("POST", "/config/apps/http/servers/srv0/routes/0", session_route)
    if result is None:
        logger.error(f"Failed to register session route for {session_id}")
        return False

    logger.info(f"Registered Caddy route: {path_prefix} -> {container_ip}:{container_port}")

    websockify_route = {
        "@id": f"websockify-{session_id}",
        "match": [
            {
                "path": ["/websockify"],
                "header": {"Cookie": [f"*kasm_session={session_id}*"]}
            }
        ],
        "handle": [
            {
                "handler": "rewrite",
                "uri": f"/websockify?password={vnc_password}" if vnc_password else "/websockify"
            },
            {
                "handler": "reverse_proxy",
                "upstreams": [{"dial": f"{container_ip}:{container_port}"}],
                "transport": {
                    "protocol": "http",
                    "tls": {"insecure_skip_verify": True}
                }
            }
        ]
    }

    if auth_header:
        websockify_route["handle"][1]["headers"] = {
            "request": {"set": {"Authorization": [auth_header]}}
        }

    result = _caddy_request("POST", "/config/apps/http/servers/srv0/routes/0", websockify_route)
    if result is None:
        logger.warning(f"Failed to register websockify route for {session_id}")
    else:
        logger.info(f"Registered websockify route for session {session_id}")

    return True


def unregister_session_route(session_id: str) -> bool:
    _caddy_request("DELETE", f"/id/websockify-{session_id}")
    result = _caddy_request("DELETE", f"/id/session-{session_id}")
    if result is not None:
        logger.info(f"Removed session route for {session_id}")
    return True


def check_caddy_ready() -> bool:
    try:
        result = _caddy_request("GET", "/config/")
        return result is not None
    except:
        return False


def sync_existing_sessions(cfg: dict, sessions: list) -> None:
    session_prefix = cfg["server"]["session_path_prefix"]
    container_port = cfg["docker"].get("container_port", 6901)

    for session_info in sessions:
        if session_info.container_ip:
            logger.info(f"Syncing route for existing session {session_info.session_id}")
            register_session_route(
                session_id=session_info.session_id,
                container_ip=session_info.container_ip,
                container_port=container_port,
                session_prefix=session_prefix,
                vnc_password=session_info.vnc_password,
            )

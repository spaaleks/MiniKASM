from gevent import monkey
monkey.patch_all()

import os
import json
import logging
import secrets
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from functools import wraps

from flask import Flask, redirect, render_template, request, session, url_for, Response
from flask_sock import Sock

from .config import load_config, get_allowed_images_for_user, get_image_config, get_user_config, get_all_instance_display_names
from .sessions import (
    verify_login,
    create_session_for_user,
    list_sessions_for_user,
    reap_idle_sessions,
    delete_session,
    user_owns_session,
    get_session_stats,
    get_session_details,
    update_session_alias,
    update_session_protection,
    pause_session,
    resume_session,
    resume_user_sessions,
    ensure_fixed_instances,
    ensure_shared_instances,
    cleanup_orphan_sessions,
    is_session_fixed,
    get_shared_sessions_for_user,
    can_user_manage_shared_session,
)
from .docker_mgr import image_exists, pull_image, parse_container_created
from . import database as db

logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

LOGIN_TOKEN_COOKIE = "minikasm_token"


def get_current_user() -> str | None:
    token = request.cookies.get(LOGIN_TOKEN_COOKIE)
    if not token:
        return None
    login_session = db.get_valid_login_session(token)
    if not login_session:
        return None
    db.update_login_session_activity(token)
    return login_session.username


def require_login(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user = get_current_user()
        if not user:
            return redirect(url_for("login_get"))
        session["user"] = user
        return f(*args, **kwargs)
    return decorated_function


ws_clients = {}
ws_clients_lock = threading.Lock()
user_ws_connections = {}
user_ws_lock = threading.Lock()


def create_app() -> Flask:
    app = Flask(__name__, template_folder="../templates", static_folder="../static")

    cfg_path = os.environ.get("CONFIG_PATH", "/config/users.yaml")
    cfg = load_config(cfg_path)

    app.secret_key = cfg["server"]["secret_key"]
    app.config["cfg"] = cfg
    app.config["cfg_path"] = cfg_path
    app.config["cfg_mtime"] = os.path.getmtime(cfg_path)

    def get_cfg():
        try:
            current_mtime = os.path.getmtime(app.config["cfg_path"])
            if current_mtime > app.config["cfg_mtime"]:
                logger.info("Config file changed, reloading...")
                new_cfg = load_config(app.config["cfg_path"])
                app.config["cfg"] = new_cfg
                app.config["cfg_mtime"] = current_mtime
                logger.info("Config reloaded successfully")
                cleanup_disabled_users(new_cfg)
                cleanup_orphan_sessions(new_cfg)
                ensure_fixed_instances(new_cfg)
                ensure_shared_instances(new_cfg)
        except Exception as e:
            logger.error(f"Failed to reload config: {e}")
        return app.config["cfg"]

    def cleanup_disabled_users(cfg):
        from .config import get_disabled_users
        disabled = get_disabled_users(cfg)
        if not disabled:
            return
        all_sessions = db.get_all_sessions()
        for session_row in all_sessions:
            if session_row.username in disabled and session_row.state == "running":
                logger.info(f"Pausing session {session_row.session_id} for disabled user {session_row.username}")
                pause_session(session_row.session_id)

    app.get_cfg = get_cfg

    @app.before_request
    def _check_config():
        get_cfg()

    @app.before_request
    def _reap():
        import random
        cfg = app.config["cfg"]
        if random.random() < 0.01:
            reap_idle_sessions(cfg)
            db.delete_expired_login_sessions()

    @app.get("/")
    @require_login
    def home():
        cfg = app.config["cfg"]
        user = session["user"]
        resume_user_sessions(cfg, user)
        sessions_list = list_sessions_for_user(cfg, user)
        shared_sessions = get_shared_sessions_for_user(cfg, user)
        all_sessions = sessions_list + shared_sessions
        all_sessions.sort(key=lambda s: (s.alias or s.session_id).lower())
        allowed_images = get_allowed_images_for_user(cfg, user)
        instance_names = get_all_instance_display_names(cfg)
        return render_template(
            "home.html",
            user=user,
            sessions=all_sessions,
            prefix=cfg["server"]["session_path_prefix"],
            allowed_images=allowed_images,
            instance_names=instance_names,
        )

    @app.get("/login")
    def login_get():
        if get_current_user():
            return redirect(url_for("home"))
        return render_template("login.html")

    @app.post("/login")
    def login_post():
        cfg = app.config["cfg"]
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if verify_login(cfg, username, password):
            token = secrets.token_urlsafe(32)
            timeout_hours = cfg["server"].get("login_session_timeout_hours", 24)
            expires_at = time.time() + (timeout_hours * 3600)
            user_agent = request.headers.get("User-Agent", "")[:256]
            ip_address = request.remote_addr

            db.create_login_session(
                token=token,
                username=username,
                expires_at=expires_at,
                user_agent=user_agent,
                ip_address=ip_address,
            )

            logger.info(f"User {username} logged in from {ip_address}")
            response = redirect(url_for("home"))
            response.set_cookie(
                LOGIN_TOKEN_COOKIE,
                token,
                httponly=True,
                samesite="Lax",
                max_age=int(timeout_hours * 3600),
            )
            return response

        logger.warning(f"Failed login attempt for user {username}")
        return render_template("login.html", error="Invalid credentials"), 401

    @app.post("/logout")
    def logout():
        token = request.cookies.get(LOGIN_TOKEN_COOKIE)
        user = get_current_user() or "unknown"
        if token:
            db.delete_login_session(token)
        session.clear()
        logger.info(f"User {user} logged out")
        response = redirect(url_for("login_get"))
        response.delete_cookie(LOGIN_TOKEN_COOKIE)
        return response

    @app.get("/api/images")
    @require_login
    def api_list_images():
        cfg = app.config["cfg"]
        user = session["user"]
        allowed = get_allowed_images_for_user(cfg, user)
        images = []
        for key, img_cfg in allowed.items():
            images.append({
                "key": key,
                "name": img_cfg.get("name", key),
                "description": img_cfg.get("description", ""),
                "default": img_cfg.get("default", False),
            })
        images.sort(key=lambda x: x["name"].lower())
        return {"images": images}

    @app.post("/api/sessions")
    @require_login
    def api_create_session():
        cfg = app.config["cfg"]
        user = session["user"]
        data = request.get_json(silent=True) or {}
        image_key = data.get("image_key")
        alias = data.get("alias")

        try:
            s = create_session_for_user(cfg, user, image_key=image_key, alias=alias)
            return {
                "sessionId": s.session_id,
                "url": f"{cfg['server']['session_path_prefix']}/{s.session_id}/",
                "imageKey": s.image_key,
                "alias": s.alias,
            }
        except ValueError as e:
            return {"error": str(e)}, 400

    @app.get("/api/sessions/<session_id>")
    @require_login
    def api_get_session(session_id: str):
        user = session["user"]
        if not user_owns_session(user, session_id):
            return {"error": "Not authorized"}, 403

        details = get_session_details(session_id)
        if details:
            return details
        return {"error": "Session not found"}, 404

    @app.delete("/api/sessions/<session_id>")
    @require_login
    def api_delete_session(session_id: str):
        cfg = app.config["cfg"]
        user = session["user"]
        if not user_owns_session(user, session_id):
            return {"error": "Not authorized"}, 403

        details = get_session_details(session_id)
        if details and details.get("is_fixed"):
            return {"error": "Fixed instances cannot be deleted"}, 403

        if details and details.get("delete_protected"):
            data = request.get_json(silent=True) or {}
            password = data.get("password", "")
            user_cfg = get_user_config(cfg, user)
            required_password = user_cfg.get("protection_password", "") if user_cfg else ""
            if not required_password or password != required_password:
                return {"error": "Invalid protection password"}, 403

        if delete_session(session_id, force=True):
            return {"ok": True}
        return {"error": "Session not found"}, 404

    @app.put("/api/sessions/<session_id>/alias")
    @require_login
    def api_update_alias(session_id: str):
        user = session["user"]
        if not user_owns_session(user, session_id):
            return {"error": "Not authorized"}, 403

        data = request.get_json(silent=True) or {}
        alias = data.get("alias")

        if alias is not None and len(alias) > 50:
            return {"error": "Alias too long (max 50 characters)"}, 400

        if update_session_alias(session_id, alias if alias else None):
            return {"ok": True, "alias": alias}
        return {"error": "Session not found"}, 404

    @app.post("/api/sessions/<session_id>/pause")
    @require_login
    def api_pause_session(session_id: str):
        cfg = app.config["cfg"]
        user = session["user"]
        details = get_session_details(session_id)

        if not user_owns_session(user, session_id):
            if not (details and details.get("is_shared") and can_user_manage_shared_session(cfg, session_id, user)):
                return {"error": "Not authorized"}, 403

        if details and (details.get("is_fixed") or details.get("is_shared")) and details.get("delete_protected"):
            return {"error": "Protected instances cannot be paused"}, 403

        if details and details.get("delete_protected"):
            data = request.get_json(silent=True) or {}
            password = data.get("password", "")
            user_cfg = get_user_config(cfg, user)
            required_password = user_cfg.get("protection_password", "") if user_cfg else ""
            if not required_password or password != required_password:
                return {"error": "Invalid protection password"}, 403

        if pause_session(session_id):
            return {"ok": True, "state": "paused"}
        return {"error": "Failed to pause session"}, 400

    @app.post("/api/sessions/<session_id>/resume")
    @require_login
    def api_resume_session(session_id: str):
        cfg = app.config["cfg"]
        user = session["user"]
        details = get_session_details(session_id)

        if not user_owns_session(user, session_id):
            if not (details and details.get("is_shared") and can_user_manage_shared_session(cfg, session_id, user)):
                return {"error": "Not authorized"}, 403

        if resume_session(cfg, session_id):
            return {"ok": True, "state": "running"}
        return {"error": "Failed to resume session"}, 400

    @app.post("/api/sessions/<session_id>/restart")
    @require_login
    def api_restart_session(session_id: str):
        cfg = app.config["cfg"]
        user = session["user"]
        details = get_session_details(session_id)

        if not details:
            return {"error": "Session not found"}, 404

        if not user_owns_session(user, session_id):
            if not (details.get("is_shared") and can_user_manage_shared_session(cfg, session_id, user)):
                return {"error": "Not authorized"}, 403

        if (details.get("is_fixed") or details.get("is_shared")) and details.get("delete_protected"):
            is_admin = False
            if details.get("is_shared"):
                is_admin = can_user_manage_shared_session(cfg, session_id, user)
            elif details.get("is_fixed"):
                is_admin = user_owns_session(user, session_id)
            if not is_admin:
                return {"error": "Protected instances can only be restarted by admins"}, 403

        if details.get("delete_protected"):
            data = request.get_json(silent=True) or {}
            password = data.get("password", "")
            user_cfg = get_user_config(cfg, user)
            required_password = user_cfg.get("protection_password", "") if user_cfg else ""
            if not required_password or password != required_password:
                return {"error": "Invalid protection password"}, 403

        import gevent
        from .sessions import restart_session

        def do_restart():
            try:
                result = restart_session(cfg, session_id)
                if result:
                    logger.info(f"Restart completed: {session_id} -> {result.session_id}")
                else:
                    logger.error(f"Restart failed for {session_id}")
            except Exception as e:
                logger.error(f"Restart error for {session_id}: {e}")

        gevent.spawn(do_restart)
        return {"ok": True, "restarting": True}

    @app.put("/api/sessions/<session_id>/protect")
    @require_login
    def api_toggle_protection(session_id: str):
        cfg = app.config["cfg"]
        user = session["user"]
        if not user_owns_session(user, session_id):
            return {"error": "Not authorized"}, 403

        data = request.get_json(silent=True) or {}
        protected = data.get("protected", True)

        details = get_session_details(session_id)
        if not details:
            return {"error": "Session not found"}, 404

        if details.get("delete_protected") and not protected:
            password = data.get("password", "")
            user_cfg = get_user_config(cfg, user)
            required_password = user_cfg.get("protection_password", "") if user_cfg else ""
            if not required_password or password != required_password:
                return {"error": "Invalid protection password"}, 403

        if update_session_protection(session_id, protected):
            return {"ok": True, "delete_protected": protected}
        return {"error": "Session not found"}, 404

    @app.get("/api/sessions/<session_id>/stats")
    @require_login
    def api_session_stats(session_id: str):
        user = session["user"]
        if not user_owns_session(user, session_id):
            return {"error": "Not authorized"}, 403

        stats = get_session_stats(session_id)
        if stats:
            return stats
        return {"error": "Session not found or not running"}, 404

    @app.get("/healthz")
    def healthz():
        return {"ok": True}

    @app.get("/api/login-sessions")
    @require_login
    def api_list_login_sessions():
        user = session["user"]
        current_token = request.cookies.get(LOGIN_TOKEN_COOKIE)
        login_sessions = db.get_login_sessions_for_user(user)
        now = time.time()
        result = []
        for ls in login_sessions:
            if ls.expires_at <= now:
                continue
            result.append({
                "token_prefix": ls.token[:8] + "...",
                "created_at": ls.created_at,
                "last_seen": ls.last_seen,
                "expires_at": ls.expires_at,
                "user_agent": ls.user_agent,
                "ip_address": ls.ip_address,
                "is_current": ls.token == current_token,
            })
        return {"sessions": result}

    @app.delete("/api/login-sessions/<token_prefix>")
    @require_login
    def api_revoke_login_session(token_prefix: str):
        user = session["user"]
        current_token = request.cookies.get(LOGIN_TOKEN_COOKIE)
        login_sessions = db.get_login_sessions_for_user(user)

        for ls in login_sessions:
            if ls.token.startswith(token_prefix.rstrip(".")):
                if ls.token == current_token:
                    return {"error": "Cannot revoke current session"}, 400
                db.delete_login_session(ls.token)
                logger.info(f"User {user} revoked login session {token_prefix}")
                return {"ok": True}

        return {"error": "Session not found"}, 404

    @app.post("/api/login-sessions/revoke-all")
    @require_login
    def api_revoke_all_login_sessions():
        user = session["user"]
        current_token = request.cookies.get(LOGIN_TOKEN_COOKIE)
        login_sessions = db.get_login_sessions_for_user(user)

        revoked = 0
        for ls in login_sessions:
            if ls.token != current_token:
                db.delete_login_session(ls.token)
                revoked += 1

        if revoked > 0:
            logger.info(f"User {user} revoked {revoked} login sessions")
        return {"ok": True, "revoked": revoked}

    @app.get("/api/image/status")
    @require_login
    def api_image_status():
        cfg = app.config["cfg"]
        image_key = request.args.get("image_key")
        if image_key:
            img_cfg = get_image_config(cfg, image_key)
            if img_cfg:
                image_name = img_cfg["image"]
            else:
                return {"error": "Unknown image"}, 400
        else:
            image_name = cfg["docker"]["session_image"]
        return {"image": image_name, "available": image_exists(image_name)}

    @app.post("/api/image/pull")
    @require_login
    def api_image_pull():
        cfg = app.config["cfg"]
        data = request.get_json(silent=True) or {}
        image_key = data.get("image_key")

        if image_key:
            img_cfg = get_image_config(cfg, image_key)
            if img_cfg:
                image_name = img_cfg["image"]
            else:
                return {"error": "Unknown image"}, 400
        else:
            image_name = cfg["docker"]["session_image"]

        if image_exists(image_name):
            return {"status": "exists", "image": image_name}

        def generate():
            yield f"data: {json.dumps({'status': 'starting', 'image': image_name})}\n\n"

            def progress_cb(line):
                pass

            success = pull_image(image_name, progress_cb)

            if success:
                yield f"data: {json.dumps({'status': 'complete', 'image': image_name})}\n\n"
            else:
                yield f"data: {json.dumps({'status': 'error', 'image': image_name})}\n\n"

        return Response(generate(), mimetype="text/event-stream")

    return app


app = create_app()
sock = Sock(app)


def ws_send(ws, msg_type, data):
    try:
        msg = json.dumps({"type": msg_type, **data})
        logger.debug(f"WS send: {msg_type}")
        ws.send(msg)
        return True
    except Exception as e:
        logger.debug(f"WS send failed: {e}")
        return False


def ws_send_to_user(user, msg_type, data, max_retries=10, retry_delay=0.3):
    import time
    for attempt in range(max_retries):
        with user_ws_lock:
            ws = user_ws_connections.get(user)
        if ws:
            if ws_send(ws, msg_type, data):
                return True
            with user_ws_lock:
                if user_ws_connections.get(user) == ws:
                    del user_ws_connections[user]
            logger.debug(f"WS send to {user} failed (attempt {attempt + 1}/{max_retries}), waiting for reconnect...")
        else:
            logger.debug(f"No WebSocket for {user} (attempt {attempt + 1}/{max_retries}), waiting...")
        if attempt < max_retries - 1:
            time.sleep(retry_delay)
    logger.warning(f"Failed to send {msg_type} to {user} after {max_retries} attempts")
    return False


def handle_subscribe_stats(ws, user, data):
    session_ids = data.get("session_ids", [])
    logger.debug(f"Subscribe stats request from {user} for {len(session_ids)} sessions")

    owned_sessions = []
    for sid in session_ids:
        if user_owns_session(user, sid):
            owned_sessions.append(sid)
        else:
            details = get_session_details(sid)
            logger.debug(f"Session {sid[:8]} details: is_shared={details.get('is_shared') if details else None}")
            if details and details.get("is_shared"):
                owned_sessions.append(sid)

    logger.debug(f"Subscribed {user} to {len(owned_sessions)} sessions: {[s[:8] for s in owned_sessions]}")

    with ws_clients_lock:
        ws_clients[id(ws)] = {
            "ws": ws,
            "user": user,
            "session_ids": owned_sessions
        }

    if owned_sessions:
        with ThreadPoolExecutor(max_workers=min(len(owned_sessions), 10)) as executor:
            future_to_sid = {executor.submit(get_session_stats, sid): sid for sid in owned_sessions}
            for future in as_completed(future_to_sid):
                sid = future_to_sid[future]
                try:
                    stats = future.result()
                    if stats:
                        ws_send(ws, "stats_update", {"session_id": sid, "stats": stats})
                except Exception as e:
                    logger.error(f"Error fetching stats for {sid[:8]}: {e}")


def handle_unsubscribe_stats(ws):
    with ws_clients_lock:
        if id(ws) in ws_clients:
            del ws_clients[id(ws)]


def handle_create_session(ws, user, data):
    cfg = app.config["cfg"]
    image_key = data.get("image_key")
    alias = data.get("alias")

    try:
        ws_send(ws, "create_progress", {
            "stage": "checking",
            "message": "Checking image availability...",
            "percent": 0
        })

        img_cfg = None
        image_name = None
        if image_key:
            img_cfg = get_image_config(cfg, image_key)
            if img_cfg:
                image_name = img_cfg["image"]
            else:
                ws_send(ws, "create_error", {"error": "Unknown image"})
                return
        else:
            image_name = cfg["docker"]["session_image"]

        if not image_exists(image_name):
            ws_send(ws, "create_progress", {
                "stage": "pulling",
                "message": f"Pulling image {image_name}...",
                "percent": 5
            })

            layer_progress = {}

            def progress_callback(line):
                layer_id = line.get("id")
                status = line.get("status", "")
                progress_detail = line.get("progressDetail", {})

                if layer_id and status in ("Downloading", "Extracting"):
                    current = progress_detail.get("current", 0)
                    total = progress_detail.get("total", 0)
                    if total > 0:
                        layer_progress[layer_id] = {
                            "status": status,
                            "current": current,
                            "total": total
                        }
                elif layer_id and status in ("Pull complete", "Already exists"):
                    layer_progress[layer_id] = {
                        "status": "complete",
                        "current": 1,
                        "total": 1
                    }

                if layer_progress:
                    total_bytes = sum(lp.get("total", 0) for lp in layer_progress.values())
                    current_bytes = sum(lp.get("current", 0) for lp in layer_progress.values())
                    if total_bytes > 0:
                        pull_percent = int((current_bytes / total_bytes) * 85) + 5
                        pull_percent = min(pull_percent, 90)
                        ws_send(ws, "create_progress", {
                            "stage": "pulling",
                            "message": f"Pulling image... {len(layer_progress)} layers",
                            "percent": pull_percent,
                            "layers": len(layer_progress),
                            "current_mb": round(current_bytes / (1024 * 1024), 1),
                            "total_mb": round(total_bytes / (1024 * 1024), 1)
                        })

            success = pull_image(image_name, progress_callback)
            if not success:
                ws_send(ws, "create_error", {"error": "Failed to pull image"})
                return

        ws_send(ws, "create_progress", {
            "stage": "creating",
            "message": "Creating container...",
            "percent": 92
        })

        s = create_session_for_user(cfg, user, image_key=image_key, alias=alias)

        logger.info(f"Session {s.session_id} created, sending completion messages")
        ws_send_to_user(user, "create_progress", {
            "stage": "complete",
            "message": "Session ready!",
            "percent": 100
        })

        ws_send_to_user(user, "session_created", {
            "sessionId": s.session_id,
            "url": f"{cfg['server']['session_path_prefix']}/{s.session_id}/",
            "imageKey": s.image_key,
            "alias": s.alias,
            "createdAt": s.created_at,
            "isFixed": s.is_fixed,
            "isShared": s.is_shared
        })
        logger.info(f"session_created message sent for {s.session_id}")

    except ValueError as e:
        ws_send(ws, "create_error", {"error": str(e)})
    except Exception as e:
        logger.error(f"Error creating session via WebSocket: {e}")
        ws_send(ws, "create_error", {"error": "Internal error creating session"})


def handle_delete_session(ws, user, data):
    cfg = app.config["cfg"]
    session_id = data.get("session_id")
    password = data.get("password")

    if not session_id:
        ws_send(ws, "delete_error", {"error": "Session ID required", "session_id": session_id})
        return

    if not user_owns_session(user, session_id):
        ws_send(ws, "delete_error", {"error": "Not authorized", "session_id": session_id})
        return

    details = get_session_details(session_id)
    if not details:
        ws_send(ws, "delete_error", {"error": "Session not found", "session_id": session_id})
        return

    if details.get("is_fixed"):
        ws_send(ws, "delete_error", {"error": "Fixed instances cannot be deleted", "session_id": session_id})
        return

    if details.get("is_shared"):
        ws_send(ws, "delete_error", {"error": "Shared instances cannot be deleted", "session_id": session_id})
        return

    if details.get("delete_protected"):
        user_cfg = get_user_config(cfg, user)
        required_password = user_cfg.get("protection_password", "") if user_cfg else ""
        if not required_password or password != required_password:
            ws_send(ws, "delete_error", {"error": "Invalid protection password", "session_id": session_id})
            return

    ws_send(ws, "delete_progress", {
        "session_id": session_id,
        "message": "Stopping container...",
        "percent": 30
    })

    logger.info(f"Deleting session {session_id}")
    if delete_session(session_id, force=True):
        logger.info(f"Session {session_id} deleted, sending session_deleted message")
        ws_send_to_user(user, "session_deleted", {"session_id": session_id, "ok": True})
        logger.info(f"session_deleted message sent for {session_id}")
    else:
        ws_send_to_user(user, "delete_error", {"error": "Failed to delete session", "session_id": session_id})


@sock.route("/ws")
def websocket_handler(ws):
    token = request.cookies.get(LOGIN_TOKEN_COOKIE)
    if not token:
        ws.close(1008, "Not authenticated")
        return
    login_session = db.get_valid_login_session(token)
    if not login_session:
        ws.close(1008, "Session expired")
        return
    user = login_session.username
    db.update_login_session_activity(token)

    logger.debug(f"WebSocket connected: {user}")

    with user_ws_lock:
        user_ws_connections[user] = ws

    try:
        while True:
            message = ws.receive()
            if message is None:
                break

            try:
                data = json.loads(message)
                msg_type = data.get("type")
                logger.debug(f"WS recv from {user}: {msg_type}")

                if msg_type == "subscribe_stats":
                    handle_subscribe_stats(ws, user, data)
                elif msg_type == "unsubscribe_stats":
                    handle_unsubscribe_stats(ws)
                elif msg_type == "create_session":
                    handle_create_session(ws, user, data)
                elif msg_type == "delete_session":
                    handle_delete_session(ws, user, data)
                else:
                    ws_send(ws, "error", {"error": f"Unknown message type: {msg_type}"})
            except json.JSONDecodeError:
                ws_send(ws, "error", {"error": "Invalid JSON"})
    except Exception as e:
        logger.error(f"WebSocket error for {user}: {e}", exc_info=True)
    finally:
        with user_ws_lock:
            if user_ws_connections.get(user) == ws:
                del user_ws_connections[user]
        handle_unsubscribe_stats(ws)
        logger.debug(f"WebSocket disconnected: {user}")


def stats_push_loop():
    while True:
        time.sleep(1)
        try:
            with ws_clients_lock:
                clients = list(ws_clients.values())

            all_session_ids = set()
            for client in clients:
                all_session_ids.update(client.get("session_ids", []))

            if not all_session_ids:
                continue

            stats_cache = {}
            with ThreadPoolExecutor(max_workers=min(len(all_session_ids), 10)) as executor:
                future_to_sid = {executor.submit(get_session_stats, sid): sid for sid in all_session_ids}
                for future in as_completed(future_to_sid):
                    sid = future_to_sid[future]
                    try:
                        stats = future.result()
                        if stats:
                            stats_cache[sid] = stats
                    except Exception as e:
                        logger.error(f"Error fetching stats for {sid[:8]}: {e}")

            for client in clients:
                ws = client["ws"]
                for sid in client.get("session_ids", []):
                    if sid in stats_cache:
                        ws_send(ws, "stats_update", {"session_id": sid, "stats": stats_cache[sid]})
        except Exception as e:
            logger.error(f"Stats push error: {e}")


def run_server():
    port = int(os.environ.get("FLASK_PORT", os.environ.get("PORT", 8080)))

    logger.info(f"Starting Flask server on port {port}")

    cfg = app.config["cfg"]

    db.init_db()
    logger.info("Database initialized")

    from .caddy_mgr import sync_existing_sessions, check_caddy_ready
    from .docker_mgr import get_all_managed_containers, get_container_ip, is_container_running, is_container_paused, LABEL_PREFIX
    from .sessions import SessionInfo

    for _ in range(30):
        if check_caddy_ready():
            logger.info("Caddy is ready")
            break
        time.sleep(0.5)
    else:
        logger.warning("Caddy not ready after 15s, continuing anyway")

    containers = get_all_managed_containers()
    existing_sessions = []
    for container in containers:
        container_running = is_container_running(container)
        container_paused = is_container_paused(container)

        if not container_running and not container_paused:
            continue

        labels = container.labels
        session_id = labels.get(f"{LABEL_PREFIX}.session_id")
        if not session_id:
            continue

        container_ip = get_container_ip(container)
        state = "paused" if container_paused else "running"

        is_fixed = labels.get(f"{LABEL_PREFIX}.is_fixed", "false").lower() == "true"
        is_shared = labels.get(f"{LABEL_PREFIX}.is_shared", "false").lower() == "true"

        db_row = db.migrate_container_to_db(
            session_id=session_id,
            container_id=container.id,
            username=labels.get(f"{LABEL_PREFIX}.username", "unknown"),
            created_at=parse_container_created(container),
            container_ip=container_ip,
            vnc_password=labels.get(f"{LABEL_PREFIX}.vnc_pw"),
            state=state,
            image_key=labels.get(f"{LABEL_PREFIX}.image_key"),
            alias=labels.get(f"{LABEL_PREFIX}.alias"),
            is_fixed=is_fixed,
            is_shared=is_shared,
        )

        if db_row and state == "running":
            session_info = SessionInfo(
                session_id=session_id,
                container_id=container.id,
                username=labels.get(f"{LABEL_PREFIX}.username", "unknown"),
                created_at=parse_container_created(container),
                container_ip=container_ip,
                vnc_password=labels.get(f"{LABEL_PREFIX}.vnc_pw"),
            )
            existing_sessions.append(session_info)

    if existing_sessions:
        logger.info(f"Found {len(existing_sessions)} running sessions, syncing routes...")
        sync_existing_sessions(cfg, existing_sessions)

    from .docker_mgr import get_container_by_session_id
    all_db_sessions = db.get_all_sessions()
    stale_count = 0
    for db_session in all_db_sessions:
        if db_session.state in ("running", "paused"):
            if db_session.is_fixed or db_session.is_shared:
                continue
            container = get_container_by_session_id(db_session.session_id)
            if container is None:
                logger.info(f"Marking stale session {db_session.session_id[:8]} as terminated (container not found)")
                db.update_session_state(db_session.session_id, "terminated")
                stale_count += 1
    if stale_count:
        logger.info(f"Cleaned up {stale_count} stale sessions")

    orphan_result = cleanup_orphan_sessions(cfg)
    orphan_count = sum(len(v) for v in orphan_result.values())
    if orphan_count:
        logger.info(f"Cleaned up {orphan_count} orphan sessions: {orphan_result}")

    fixed_created = ensure_fixed_instances(cfg)
    if fixed_created:
        logger.info(f"Created {len(fixed_created)} fixed instances")

    shared_created = ensure_shared_instances(cfg)
    if shared_created:
        logger.info(f"Created {len(shared_created)} shared instances")

    stats_thread = threading.Thread(target=stats_push_loop, daemon=True)
    stats_thread.start()
    logger.info("Stats push thread started")

    from gevent.pywsgi import WSGIServer

    server = WSGIServer(("0.0.0.0", port), app)
    logger.info(f"Server running on port {port}")
    server.serve_forever()


if __name__ == "__main__":
    run_server()

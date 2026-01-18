import os
import json
import logging

from flask import Flask, redirect, render_template, request, session, url_for, Response

from .config import load_config, get_allowed_images_for_user, get_image_config, get_user_config
from .sessions import (
    require_login,
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
)
from .docker_mgr import image_exists, pull_image
from . import database as db

logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


def create_app() -> Flask:
    app = Flask(__name__, template_folder="../templates", static_folder="../static")

    cfg_path = os.environ.get("CONFIG_PATH", "/config/users.yaml")
    cfg = load_config(cfg_path)

    app.secret_key = cfg["server"]["secret_key"]
    app.config["cfg"] = cfg

    @app.before_request
    def _reap():
        import random
        if random.random() < 0.01:
            reap_idle_sessions(cfg)

    @app.get("/")
    @require_login
    def home():
        user = session["user"]
        sessions_list = list_sessions_for_user(cfg, user)
        allowed_images = get_allowed_images_for_user(cfg, user)
        return render_template(
            "home.html",
            user=user,
            sessions=sessions_list,
            prefix=cfg["server"]["session_path_prefix"],
            allowed_images=allowed_images,
        )

    @app.get("/login")
    def login_get():
        if "user" in session:
            return redirect(url_for("home"))
        return render_template("login.html")

    @app.post("/login")
    def login_post():
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if verify_login(cfg, username, password):
            session["user"] = username
            logger.info(f"User {username} logged in")
            return redirect(url_for("home"))

        logger.warning(f"Failed login attempt for user {username}")
        return render_template("login.html", error="Invalid credentials"), 401

    @app.post("/logout")
    def logout():
        user = session.get("user", "unknown")
        session.clear()
        logger.info(f"User {user} logged out")
        return redirect(url_for("login_get"))

    @app.get("/api/images")
    @require_login
    def api_list_images():
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
        user = session["user"]
        if not user_owns_session(user, session_id):
            return {"error": "Not authorized"}, 403

        details = get_session_details(session_id)
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
        user = session["user"]
        if not user_owns_session(user, session_id):
            return {"error": "Not authorized"}, 403

        details = get_session_details(session_id)
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
        user = session["user"]
        if not user_owns_session(user, session_id):
            return {"error": "Not authorized"}, 403

        if resume_session(cfg, session_id):
            return {"ok": True, "state": "running"}
        return {"error": "Failed to resume session"}, 400

    @app.post("/api/sessions/<session_id>/restart")
    @require_login
    def api_restart_session(session_id: str):
        user = session["user"]
        if not user_owns_session(user, session_id):
            return {"error": "Not authorized"}, 403

        details = get_session_details(session_id)
        if not details:
            return {"error": "Session not found"}, 404

        if details.get("delete_protected"):
            data = request.get_json(silent=True) or {}
            password = data.get("password", "")
            user_cfg = get_user_config(cfg, user)
            required_password = user_cfg.get("protection_password", "") if user_cfg else ""
            if not required_password or password != required_password:
                return {"error": "Invalid protection password"}, 403

        from .sessions import restart_session
        result = restart_session(cfg, session_id)
        if result:
            return {
                "ok": True,
                "sessionId": result.session_id,
                "url": f"{cfg['server']['session_path_prefix']}/{result.session_id}/",
            }
        return {"error": "Failed to restart session"}, 400

    @app.put("/api/sessions/<session_id>/protect")
    @require_login
    def api_toggle_protection(session_id: str):
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

    @app.get("/api/image/status")
    @require_login
    def api_image_status():
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


def run_server():
    port = int(os.environ.get("FLASK_PORT", os.environ.get("PORT", 8080)))

    logger.info(f"Starting Flask server on port {port}")

    cfg = app.config["cfg"]

    db.init_db()
    logger.info("Database initialized")

    from .caddy_mgr import sync_existing_sessions, check_caddy_ready
    from .docker_mgr import get_all_managed_containers, get_container_ip, is_container_running, is_container_paused, LABEL_PREFIX
    from .sessions import SessionInfo

    import time
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

        db_row = db.migrate_container_to_db(
            session_id=session_id,
            container_id=container.id,
            username=labels.get(f"{LABEL_PREFIX}.username", "unknown"),
            created_at=container.attrs.get("Created", time.time()),
            container_ip=container_ip,
            vnc_password=labels.get(f"{LABEL_PREFIX}.vnc_pw"),
            state=state,
        )

        if db_row and state == "running":
            session_info = SessionInfo(
                session_id=session_id,
                container_id=container.id,
                username=labels.get(f"{LABEL_PREFIX}.username", "unknown"),
                created_at=container.attrs.get("Created", time.time()),
                container_ip=container_ip,
                vnc_password=labels.get(f"{LABEL_PREFIX}.vnc_pw"),
            )
            existing_sessions.append(session_info)

    if existing_sessions:
        logger.info(f"Found {len(existing_sessions)} running sessions, syncing routes...")
        sync_existing_sessions(cfg, existing_sessions)

    from gevent import pywsgi
    server = pywsgi.WSGIServer(("0.0.0.0", port), app)
    server.serve_forever()


if __name__ == "__main__":
    run_server()

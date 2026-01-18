import secrets
import time
import bcrypt
import logging
from functools import wraps
from typing import Any, Callable
from dataclasses import dataclass, field
from flask import session, redirect, url_for

from .docker_mgr import (
    create_session_container,
    get_containers_for_user,
    get_all_managed_containers,
    get_container_by_session_id,
    get_container_ip,
    get_published_port,
    get_container_stats,
    stop_container,
    is_container_running,
    is_container_paused,
    pause_container,
    unpause_container,
    wait_for_ready,
    LABEL_PREFIX,
)
from .config import get_user_config, get_allowed_images_for_user, get_image_config
from . import database as db

logger = logging.getLogger(__name__)


@dataclass
class SessionInfo:
    session_id: str
    container_id: str
    username: str
    created_at: float
    last_seen: float = field(default_factory=time.time)
    container_ip: str | None = None
    published_port: int | None = None
    vnc_password: str | None = None
    image_key: str | None = None
    alias: str | None = None
    state: str = "running"
    delete_protected: bool = False


def require_login(f: Callable) -> Callable:
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user" not in session:
            return redirect(url_for("login_get"))
        return f(*args, **kwargs)
    return decorated_function


def verify_login(cfg: dict[str, Any], username: str, password: str) -> bool:
    user_cfg = get_user_config(cfg, username)
    if not user_cfg:
        return False

    password_hash = user_cfg.get("password_hash_bcrypt", "")
    if not password_hash:
        return False

    try:
        return bcrypt.checkpw(
            password.encode("utf-8"),
            password_hash.encode("utf-8")
        )
    except Exception as e:
        logger.error(f"Error verifying password: {e}")
        return False


def _db_to_session_info(row: db.SessionRow) -> SessionInfo:
    return SessionInfo(
        session_id=row.session_id,
        container_id=row.container_id,
        username=row.username,
        created_at=row.created_at,
        last_seen=row.last_seen,
        container_ip=row.container_ip,
        vnc_password=row.vnc_password,
        image_key=row.image_key,
        alias=row.alias,
        state=row.state,
        delete_protected=row.delete_protected,
    )


def create_session_for_user(
    cfg: dict[str, Any],
    username: str,
    image_key: str | None = None,
    alias: str | None = None,
) -> SessionInfo:
    user_cfg = get_user_config(cfg, username)
    if not user_cfg:
        raise ValueError(f"User {username} not found in config")

    user_sessions = list_sessions_for_user(cfg, username)
    max_sessions = user_cfg.get("max_sessions", 1)
    if len(user_sessions) >= max_sessions:
        raise ValueError(f"User {username} has reached max sessions ({max_sessions})")

    all_containers = get_all_managed_containers()
    max_total = cfg["server"].get("max_sessions_total", 50)
    if len(all_containers) >= max_total:
        raise ValueError(f"Global session limit reached ({max_total})")

    # Determine image to use
    allowed_images = get_allowed_images_for_user(cfg, username)
    if image_key:
        if image_key not in allowed_images:
            raise ValueError(f"Image '{image_key}' is not allowed for user {username}")
    else:
        # Use user's default or first allowed image
        image_key = user_cfg.get("default_image")
        if not image_key or image_key not in allowed_images:
            # Find default image or use first allowed
            for key, img_cfg in allowed_images.items():
                if img_cfg.get("default"):
                    image_key = key
                    break
            else:
                image_key = next(iter(allowed_images)) if allowed_images else None

    if not image_key:
        raise ValueError("No allowed images configured")

    image_cfg = get_image_config(cfg, image_key)
    if not image_cfg:
        raise ValueError(f"Image config not found for '{image_key}'")

    session_id = secrets.token_urlsafe(16)

    # Determine if user has persistent volume enabled
    persistent_volume = user_cfg.get("persistent_volume", False)

    container = create_session_container(
        cfg, username, session_id,
        image_key=image_key,
        image_config=image_cfg,
        persistent_volume=persistent_volume,
    )

    container_port = cfg["docker"].get("container_port", 6901)
    time.sleep(2)
    container_ip = get_container_ip(container)

    if container_ip:
        wait_for_ready(container_ip, container_port, timeout=90)

    vnc_password = container.labels.get(f"{LABEL_PREFIX}.vnc_pw")

    now = time.time()

    # Save to database
    db_row = db.create_session(
        session_id=session_id,
        container_id=container.id,
        username=username,
        created_at=now,
        container_ip=container_ip,
        vnc_password=vnc_password,
        image_key=image_key,
        alias=alias,
        state="running",
    )

    session_info = _db_to_session_info(db_row)

    if container_ip:
        from .caddy_mgr import register_session_route
        session_prefix = cfg["server"]["session_path_prefix"]
        register_session_route(
            session_id=session_id,
            container_ip=container_ip,
            container_port=container_port,
            session_prefix=session_prefix,
            vnc_password=vnc_password,
        )

    logger.info(f"Created session {session_id} for user {username} with image {image_key}")
    return session_info


def list_sessions_for_user(cfg: dict[str, Any], username: str) -> list[SessionInfo]:
    containers = get_containers_for_user(username)
    sessions = []

    for container in containers:
        labels = container.labels
        session_id = labels.get(f"{LABEL_PREFIX}.session_id")
        if not session_id:
            continue

        # Check container state
        container_running = is_container_running(container)
        container_paused = is_container_paused(container)

        if not container_running and not container_paused:
            # Container is stopped/exited, skip it
            continue

        # Get from database or create record
        db_row = db.get_session(session_id)
        if db_row:
            session_info = _db_to_session_info(db_row)
            # Update IP if missing
            if not session_info.container_ip:
                container_ip = get_container_ip(container)
                if container_ip:
                    db.update_session_ip(session_id, container_ip)
                    session_info.container_ip = container_ip
            # Sync state with container
            actual_state = "paused" if container_paused else "running"
            if session_info.state != actual_state:
                db.update_session_state(session_id, actual_state)
                session_info.state = actual_state
        else:
            # Migrate container to database
            container_ip = get_container_ip(container)
            state = "paused" if container_paused else "running"
            db_row = db.migrate_container_to_db(
                session_id=session_id,
                container_id=container.id,
                username=username,
                created_at=container.attrs.get("Created", time.time()),
                container_ip=container_ip,
                vnc_password=labels.get(f"{LABEL_PREFIX}.vnc_pw"),
                state=state,
            )
            if db_row:
                session_info = _db_to_session_info(db_row)
            else:
                continue

        sessions.append(session_info)

    return sessions


def get_session(session_id: str) -> SessionInfo | None:
    db_row = db.get_session(session_id)
    if db_row:
        return _db_to_session_info(db_row)

    # Fallback: check container directly
    container = get_container_by_session_id(session_id)
    if not container:
        return None

    container_running = is_container_running(container)
    container_paused = is_container_paused(container)

    if not container_running and not container_paused:
        return None

    labels = container.labels
    username = labels.get(f"{LABEL_PREFIX}.username", "unknown")
    state = "paused" if container_paused else "running"

    # Migrate to database
    db_row = db.migrate_container_to_db(
        session_id=session_id,
        container_id=container.id,
        username=username,
        created_at=container.attrs.get("Created", time.time()),
        container_ip=get_container_ip(container),
        vnc_password=labels.get(f"{LABEL_PREFIX}.vnc_pw"),
        state=state,
    )
    if db_row:
        return _db_to_session_info(db_row)
    return None


def get_session_details(session_id: str) -> dict[str, Any] | None:
    session_info = get_session(session_id)
    if not session_info:
        return None

    return {
        "session_id": session_info.session_id,
        "container_id": session_info.container_id,
        "username": session_info.username,
        "image_key": session_info.image_key,
        "alias": session_info.alias,
        "state": session_info.state,
        "delete_protected": session_info.delete_protected,
        "created_at": session_info.created_at,
        "last_seen": session_info.last_seen,
    }


def update_session_activity(session_id: str) -> None:
    db.update_session_activity(session_id)


def update_session_alias(session_id: str, alias: str | None) -> bool:
    return db.update_session_alias(session_id, alias)


def update_session_protection(session_id: str, protected: bool) -> bool:
    return db.update_session_protection(session_id, protected)


def pause_session(session_id: str) -> bool:
    container = get_container_by_session_id(session_id)
    if not container or not is_container_running(container):
        return False

    if pause_container(container):
        db.update_session_state(session_id, "paused")
        logger.info(f"Paused session {session_id}")
        return True
    return False


def resume_session(cfg: dict[str, Any], session_id: str) -> bool:
    container = get_container_by_session_id(session_id)
    if not container or not is_container_paused(container):
        return False

    if unpause_container(container):
        db.update_session_state(session_id, "running")

        # Re-register route in case IP changed
        container_ip = get_container_ip(container)
        if container_ip:
            db.update_session_ip(session_id, container_ip)
            from .caddy_mgr import register_session_route
            session_info = get_session(session_id)
            if session_info:
                container_port = cfg["docker"].get("container_port", 6901)
                session_prefix = cfg["server"]["session_path_prefix"]
                register_session_route(
                    session_id=session_id,
                    container_ip=container_ip,
                    container_port=container_port,
                    session_prefix=session_prefix,
                    vnc_password=session_info.vnc_password,
                )

        logger.info(f"Resumed session {session_id}")
        return True
    return False


def delete_session(session_id: str, force: bool = False) -> bool:
    if not force and db.is_session_protected(session_id):
        logger.warning(f"Cannot delete protected session {session_id}")
        return False

    from .caddy_mgr import unregister_session_route
    unregister_session_route(session_id)

    container = get_container_by_session_id(session_id)
    if container:
        stop_container(container)

    db.delete_session(session_id)
    logger.info(f"Deleted session {session_id}")
    return True


def restart_session(cfg: dict[str, Any], session_id: str) -> SessionInfo | None:
    from .docker_mgr import pull_image
    from .caddy_mgr import unregister_session_route, register_session_route

    db_row = db.get_session(session_id)
    if not db_row:
        return None

    username = db_row.username
    image_key = db_row.image_key
    alias = db_row.alias
    delete_protected = db_row.delete_protected

    user_cfg = get_user_config(cfg, username)
    if not user_cfg:
        return None

    image_cfg = get_image_config(cfg, image_key) if image_key else None
    if image_cfg:
        image_name = image_cfg.get("image", cfg["docker"]["session_image"])
        pull_on_restart = image_cfg.get("pull_on_restart", True)
    else:
        image_name = cfg["docker"]["session_image"]
        pull_on_restart = True

    if pull_on_restart:
        pull_image(image_name, None)

    unregister_session_route(session_id)
    container = get_container_by_session_id(session_id)
    if container:
        stop_container(container)
    db.delete_session(session_id)

    new_session_id = secrets.token_urlsafe(16)
    persistent_volume = user_cfg.get("persistent_volume", False)

    from .docker_mgr import create_session_container
    new_container = create_session_container(
        cfg, username, new_session_id,
        image_key=image_key,
        image_config=image_cfg,
        persistent_volume=persistent_volume,
    )

    container_port = cfg["docker"].get("container_port", 6901)
    time.sleep(2)
    container_ip = get_container_ip(new_container)

    if container_ip:
        wait_for_ready(container_ip, container_port, timeout=90)

    vnc_password = new_container.labels.get(f"{LABEL_PREFIX}.vnc_pw")
    now = time.time()

    db_row = db.create_session(
        session_id=new_session_id,
        container_id=new_container.id,
        username=username,
        created_at=now,
        container_ip=container_ip,
        vnc_password=vnc_password,
        image_key=image_key,
        alias=alias,
        state="running",
    )

    if delete_protected:
        db.update_session_protection(new_session_id, True)

    session_info = _db_to_session_info(db_row)
    session_info.delete_protected = delete_protected

    if container_ip:
        session_prefix = cfg["server"]["session_path_prefix"]
        register_session_route(
            session_id=new_session_id,
            container_ip=container_ip,
            container_port=container_port,
            session_prefix=session_prefix,
            vnc_password=vnc_password,
        )

    logger.info(f"Restarted session {session_id} -> {new_session_id} with fresh image")
    return session_info


def reap_idle_sessions(cfg: dict[str, Any]) -> int:
    timeout = cfg["server"].get("idle_timeout_seconds", 600)
    now = time.time()
    reaped = 0

    containers = get_all_managed_containers()
    for container in containers:
        labels = container.labels
        session_id = labels.get(f"{LABEL_PREFIX}.session_id")
        if not session_id:
            continue

        db_row = db.get_session(session_id)
        if db_row:
            last_seen = db_row.last_seen
            # Don't reap protected or paused sessions
            if db_row.delete_protected or db_row.state == "paused":
                continue
        else:
            last_seen = now - timeout + 60

        if now - last_seen > timeout:
            logger.info(f"Reaping idle session {session_id}")
            delete_session(session_id, force=True)
            reaped += 1

    return reaped


def user_owns_session(username: str, session_id: str) -> bool:
    session_info = get_session(session_id)
    if not session_info:
        return False
    return session_info.username == username


def get_session_stats(session_id: str) -> dict[str, float] | None:
    container = get_container_by_session_id(session_id)
    if not container or not is_container_running(container):
        return None
    return get_container_stats(container)

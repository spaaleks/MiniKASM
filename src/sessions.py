import secrets
import time
import bcrypt
import logging
import gevent
from gevent.lock import BoundedSemaphore
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
    parse_container_created,
    LABEL_PREFIX,
)
from .config import get_user_config, get_allowed_images_for_user, get_image_config, get_image_limit_for_user
from . import database as db

logger = logging.getLogger(__name__)

# Lock dictionary for per-session operations
_session_locks: dict[str, BoundedSemaphore] = {}
_session_locks_lock = BoundedSemaphore(1)


def _get_session_lock(session_id: str) -> BoundedSemaphore:
    """Get or create a lock for a specific session."""
    with _session_locks_lock:
        if session_id not in _session_locks:
            _session_locks[session_id] = BoundedSemaphore(1)
        return _session_locks[session_id]


def _cleanup_session_lock(session_id: str) -> None:
    """Remove a session lock after the session is deleted."""
    with _session_locks_lock:
        _session_locks.pop(session_id, None)


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
    is_fixed: bool = False
    is_shared: bool = False


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

    if not user_cfg.get("enable", True):
        logger.info(f"Login denied for disabled user: {username}")
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
        is_fixed=row.is_fixed,
        is_shared=row.is_shared,
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
    non_fixed_sessions = [s for s in user_sessions if not s.is_fixed]
    max_sessions = user_cfg.get("max_sessions", 1)
    if len(non_fixed_sessions) >= max_sessions:
        raise ValueError(f"User {username} has reached max sessions ({max_sessions})")

    all_containers = get_all_managed_containers()
    max_total = cfg["server"].get("max_sessions_total", 50)
    if len(all_containers) >= max_total:
        raise ValueError(f"Global session limit reached ({max_total})")

    allowed_images = get_allowed_images_for_user(cfg, username)
    if image_key:
        if image_key not in allowed_images:
            raise ValueError(f"Image '{image_key}' is not allowed for user {username}")
    else:
        image_key = user_cfg.get("default_image")
        if not image_key or image_key not in allowed_images:
            for key, img_cfg in allowed_images.items():
                if img_cfg.get("default"):
                    image_key = key
                    break
            else:
                image_key = next(iter(allowed_images)) if allowed_images else None

    if not image_key:
        raise ValueError("No allowed images configured")

    image_limit = get_image_limit_for_user(cfg, username, image_key)
    if image_limit is not None:
        image_session_count = sum(1 for s in non_fixed_sessions if s.image_key == image_key)
        if image_session_count >= image_limit:
            raise ValueError(f"User {username} has reached max sessions for image '{image_key}' ({image_limit})")

    image_cfg = get_image_config(cfg, image_key)
    if not image_cfg:
        raise ValueError(f"Image config not found for '{image_key}'")

    session_id = secrets.token_urlsafe(16)
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
    seen_session_ids = set()

    for container in containers:
        labels = container.labels
        session_id = labels.get(f"{LABEL_PREFIX}.session_id")
        if not session_id:
            continue

        container_running = is_container_running(container)
        container_paused = is_container_paused(container)

        if not container_running and not container_paused:
            continue

        seen_session_ids.add(session_id)

        db_row = db.get_session(session_id)
        if db_row:
            session_info = _db_to_session_info(db_row)
            if not session_info.container_ip:
                container_ip = get_container_ip(container)
                if container_ip:
                    db.update_session_ip(session_id, container_ip)
                    session_info.container_ip = container_ip
            # Don't override "restarting" state
            if session_info.state != "restarting":
                actual_state = "paused" if container_paused else "running"
                if session_info.state != actual_state:
                    db.update_session_state(session_id, actual_state)
                    session_info.state = actual_state
        else:
            container_ip = get_container_ip(container)
            state = "paused" if container_paused else "running"
            db_row = db.migrate_container_to_db(
                session_id=session_id,
                container_id=container.id,
                username=username,
                created_at=parse_container_created(container),
                container_ip=container_ip,
                vnc_password=labels.get(f"{LABEL_PREFIX}.vnc_pw"),
                state=state,
                image_key=labels.get(f"{LABEL_PREFIX}.image_key"),
                alias=labels.get(f"{LABEL_PREFIX}.alias"),
                is_fixed=labels.get(f"{LABEL_PREFIX}.is_fixed", "false").lower() == "true",
                is_shared=labels.get(f"{LABEL_PREFIX}.is_shared", "false").lower() == "true",
            )
            if db_row:
                session_info = _db_to_session_info(db_row)
            else:
                continue

        sessions.append(session_info)

    # Also include sessions that are in "restarting" state (container may be gone)
    db_sessions = db.get_sessions_for_user(username)
    for db_row in db_sessions:
        if db_row.session_id not in seen_session_ids and db_row.state == "restarting":
            sessions.append(_db_to_session_info(db_row))

    return sessions


def get_session(session_id: str) -> SessionInfo | None:
    db_row = db.get_session(session_id)
    if db_row:
        return _db_to_session_info(db_row)

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
    db_row = db.migrate_container_to_db(
        session_id=session_id,
        container_id=container.id,
        username=username,
        created_at=parse_container_created(container),
        container_ip=get_container_ip(container),
        vnc_password=labels.get(f"{LABEL_PREFIX}.vnc_pw"),
        state=state,
        image_key=labels.get(f"{LABEL_PREFIX}.image_key"),
        alias=labels.get(f"{LABEL_PREFIX}.alias"),
        is_fixed=labels.get(f"{LABEL_PREFIX}.is_fixed", "false").lower() == "true",
        is_shared=labels.get(f"{LABEL_PREFIX}.is_shared", "false").lower() == "true",
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
        "is_fixed": session_info.is_fixed,
        "is_shared": session_info.is_shared,
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


def delete_session(session_id: str, force: bool = False, allow_fixed: bool = False) -> bool:
    session = get_session(session_id)
    if session and session.is_fixed and not allow_fixed:
        logger.warning(f"Cannot delete fixed session {session_id}")
        return False

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
    from .docker_mgr import pull_image, image_exists
    from .caddy_mgr import unregister_session_route, register_session_route
    from .config import get_shared_instance_by_id

    # Acquire lock for this session to prevent concurrent operations
    lock = _get_session_lock(session_id)
    if not lock.acquire(blocking=False):
        logger.warning(f"Session {session_id} is already being operated on")
        return None

    try:
        db_row = db.get_session(session_id)
        if not db_row:
            return None

        # Skip if already restarting
        if db_row.state == "restarting":
            logger.warning(f"Session {session_id} is already restarting")
            return None

        username = db_row.username
        image_key = db_row.image_key
        alias = db_row.alias
        delete_protected = db_row.delete_protected
        is_shared = db_row.is_shared
        is_fixed = db_row.is_fixed

        # Mark as restarting immediately
        db.update_session_state(session_id, "restarting")

        if is_shared:
            shared_config = get_shared_instance_by_id(cfg, alias)
            if not shared_config:
                db.update_session_state(session_id, "running")
                return None
            persistent_volume = False
            cpu_limit = shared_config.get("cpu_limit")
            mem_limit = shared_config.get("mem_limit")
            shm_size = shared_config.get("shm_size")
        else:
            user_cfg = get_user_config(cfg, username)
            if not user_cfg:
                db.update_session_state(session_id, "running")
                return None
            persistent_volume = user_cfg.get("persistent_volume", False)
            if is_fixed:
                from .config import get_fixed_instance_by_id
                fixed_config = get_fixed_instance_by_id(cfg, alias)
                cpu_limit = fixed_config.get("cpu_limit") if fixed_config else None
                mem_limit = fixed_config.get("mem_limit") if fixed_config else None
                shm_size = fixed_config.get("shm_size") if fixed_config else None
            else:
                cpu_limit = None
                mem_limit = None
                shm_size = None

        image_cfg = get_image_config(cfg, image_key) if image_key else None
        if image_cfg:
            image_name = image_cfg.get("image", cfg["docker"]["session_image"])
            pull_on_restart = image_cfg.get("pull_on_restart", True)
        else:
            image_name = cfg["docker"]["session_image"]
            pull_on_restart = True

        if pull_on_restart:
            if not pull_image(image_name, None):
                logger.error(f"Failed to pull image {image_name}")
                db.update_session_state(session_id, "running")
                return None

        # Stop old container
        unregister_session_route(session_id)
        container = get_container_by_session_id(session_id)
        if container:
            stop_container(container)

        # Create new container with new session ID
        new_session_id = secrets.token_urlsafe(16)

        from .docker_mgr import create_session_container
        new_container = create_session_container(
            cfg, username, new_session_id,
            image_key=image_key,
            image_config=image_cfg,
            persistent_volume=persistent_volume,
            is_fixed=is_fixed,
            is_shared=is_shared,
            alias=alias,
            cpu_limit_override=cpu_limit,
            mem_limit_override=mem_limit,
            shm_size_override=shm_size,
        )

        container_port = cfg["docker"].get("container_port", 6901)
        time.sleep(2)
        container_ip = get_container_ip(new_container)

        if container_ip:
            wait_for_ready(container_ip, container_port, timeout=90)

        vnc_password = new_container.labels.get(f"{LABEL_PREFIX}.vnc_pw")
        now = time.time()

        # Now delete old session and create new one
        db.delete_session(session_id)

        new_db_row = db.create_session(
            session_id=new_session_id,
            container_id=new_container.id,
            username=username,
            created_at=now,
            container_ip=container_ip,
            vnc_password=vnc_password,
            image_key=image_key,
            alias=alias,
            state="running",
            is_fixed=is_fixed,
            is_shared=is_shared,
        )

        if delete_protected:
            db.update_session_protection(new_session_id, True)

        session_info = _db_to_session_info(new_db_row)
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
    except Exception as e:
        logger.error(f"Error restarting session {session_id}: {e}")
        # Try to restore state if possible
        if db.get_session(session_id):
            db.update_session_state(session_id, "running")
        raise
    finally:
        lock.release()
        _cleanup_session_lock(session_id)


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
            if db_row.delete_protected or db_row.state == "paused":
                continue
        else:
            last_seen = now - timeout + 60

        if now - last_seen > timeout:
            if db_row and db_row.is_shared:
                logger.info(f"Deleting idle shared session {session_id}")
                delete_session(session_id, force=True)
            else:
                logger.info(f"Pausing idle session {session_id}")
                pause_session(session_id)
            reaped += 1

    return reaped


def resume_user_sessions(cfg: dict[str, Any], username: str) -> int:
    resumed = 0
    user_sessions = db.get_sessions_for_user(username)
    for session_row in user_sessions:
        if session_row.state == "paused" and not session_row.is_shared:
            if resume_session(cfg, session_row.session_id):
                logger.info(f"Auto-resumed session {session_row.session_id} for user {username}")
                resumed += 1
    return resumed


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


def is_session_fixed(session_id: str) -> bool:
    session = get_session(session_id)
    return session.is_fixed if session else False


def _get_container_resource_limits(container) -> dict[str, str]:
    labels = container.labels
    return {
        "cpu_limit": labels.get(f"{LABEL_PREFIX}.cpu_limit"),
        "mem_limit": labels.get(f"{LABEL_PREFIX}.mem_limit"),
        "shm_size": labels.get(f"{LABEL_PREFIX}.shm_size"),
    }


def _resource_limits_changed(
    container,
    cfg: dict[str, Any],
    username: str,
    cpu_limit: float | None,
    mem_limit: str | None,
    shm_size: str | None,
) -> bool:
    from .config import get_user_config

    current = _get_container_resource_limits(container)
    user_cfg = get_user_config(cfg, username) or {}
    docker_cfg = cfg["docker"]

    effective_cpu = cpu_limit if cpu_limit is not None else user_cfg.get("cpu_limit", 1.0)
    effective_mem = mem_limit if mem_limit is not None else user_cfg.get("mem_limit", "512m")
    effective_shm = shm_size if shm_size is not None else user_cfg.get("shm_size", docker_cfg.get("shm_size", "512m"))

    current_cpu = float(current["cpu_limit"]) if current["cpu_limit"] else None
    current_mem = current["mem_limit"]
    current_shm = current["shm_size"]

    if current_cpu is None or current_mem is None or current_shm is None:
        return False

    return (
        current_cpu != effective_cpu or
        current_mem != effective_mem or
        current_shm != effective_shm
    )


def create_fixed_instance(
    cfg: dict[str, Any],
    username: str,
    image_key: str,
    instance_id: str,
    protected: bool = False,
    cpu_limit: float | None = None,
    mem_limit: str | None = None,
    shm_size: str | None = None,
) -> SessionInfo:
    from .config import get_user_config, get_image_config

    user_cfg = get_user_config(cfg, username)
    if not user_cfg:
        raise ValueError(f"User {username} not found in config")

    image_cfg = get_image_config(cfg, image_key)
    if not image_cfg:
        raise ValueError(f"Image config not found for '{image_key}'")

    session_id = secrets.token_urlsafe(16)
    persistent_volume = user_cfg.get("persistent_volume", False)

    container = create_session_container(
        cfg, username, session_id,
        image_key=image_key,
        image_config=image_cfg,
        persistent_volume=persistent_volume,
        is_fixed=True,
        alias=instance_id,
        cpu_limit_override=cpu_limit,
        mem_limit_override=mem_limit,
        shm_size_override=shm_size,
    )

    container_port = cfg["docker"].get("container_port", 6901)
    time.sleep(2)
    container_ip = get_container_ip(container)

    if container_ip:
        wait_for_ready(container_ip, container_port, timeout=90)

    vnc_password = container.labels.get(f"{LABEL_PREFIX}.vnc_pw")
    now = time.time()

    db_row = db.create_session(
        session_id=session_id,
        container_id=container.id,
        username=username,
        created_at=now,
        container_ip=container_ip,
        vnc_password=vnc_password,
        image_key=image_key,
        alias=instance_id,
        state="running",
        is_fixed=True,
    )

    if protected:
        db.update_session_protection(session_id, True)

    session_info = _db_to_session_info(db_row)
    session_info.delete_protected = protected

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

    logger.info(f"Created fixed instance {session_id} for user {username} with image {image_key}")
    return session_info


def ensure_fixed_instances(cfg: dict[str, Any]) -> list[SessionInfo]:
    from .config import get_fixed_instances_for_user

    created = []
    all_users = {user["username"] for user in cfg["users"]}

    for username in all_users:
        fixed_configs = get_fixed_instances_for_user(cfg, username)
        config_ids = {inst["id"] for inst in fixed_configs}
        config_by_id = {inst["id"]: inst for inst in fixed_configs}

        user_sessions = list_sessions_for_user(cfg, username)
        fixed_sessions = [s for s in user_sessions if s.is_fixed]
        existing_by_alias = {s.alias: s for s in fixed_sessions}

        db_sessions = db.get_sessions_for_user(username)
        db_fixed_sessions = [s for s in db_sessions if s.is_fixed]

        for db_sess in db_fixed_sessions:
            if db_sess.state == "terminated" and db_sess.alias in config_ids:
                logger.info(f"Removing terminated DB record for fixed instance '{db_sess.alias}'")
                db.delete_session(db_sess.session_id)

        for inst in fixed_configs:
            existing_session = existing_by_alias.get(inst["id"])

            # Skip if session is currently restarting
            if existing_session and existing_session.state == "restarting":
                continue

            if existing_session:
                container = get_container_by_session_id(existing_session.session_id)
                if container and _resource_limits_changed(
                    container, cfg, username,
                    inst.get("cpu_limit"), inst.get("mem_limit"), inst.get("shm_size")
                ):
                    logger.info(f"Resource limits changed for fixed instance '{inst['id']}', recreating")
                    preserved_protection = existing_session.delete_protected
                    delete_session(existing_session.session_id, force=True, allow_fixed=True)
                    try:
                        session = create_fixed_instance(
                            cfg,
                            username=inst["username"],
                            image_key=inst["image"],
                            instance_id=inst["id"],
                            protected=preserved_protection,
                            cpu_limit=inst.get("cpu_limit"),
                            mem_limit=inst.get("mem_limit"),
                            shm_size=inst.get("shm_size"),
                        )
                        created.append(session)
                    except Exception as e:
                        logger.error(f"Failed to recreate fixed instance {inst['id']}: {e}")
                else:
                    config_protected = inst.get("protected", False)
                    if existing_session.delete_protected != config_protected:
                        db.update_session_protection(existing_session.session_id, config_protected)
                        logger.info(f"Synced protection status for fixed instance '{inst['id']}' to {config_protected}")
            else:
                stale_db_session = None
                preserved_protection = None
                skip_create = False
                for db_sess in db_fixed_sessions:
                    if db_sess.alias == inst["id"] and db_sess.state != "terminated":
                        # Skip if session is restarting
                        if db_sess.state == "restarting":
                            skip_create = True
                            break
                        container = get_container_by_session_id(db_sess.session_id)
                        if container is None:
                            stale_db_session = db_sess
                            preserved_protection = db_sess.delete_protected
                        break

                if skip_create:
                    continue

                if stale_db_session:
                    logger.info(f"Removing stale DB record for fixed instance '{inst['id']}' (container missing, preserving protection={preserved_protection})")
                    db.delete_session(stale_db_session.session_id)

                protection = preserved_protection if preserved_protection is not None else inst.get("protected", False)

                try:
                    session = create_fixed_instance(
                        cfg,
                        username=inst["username"],
                        image_key=inst["image"],
                        instance_id=inst["id"],
                        protected=protection,
                        cpu_limit=inst.get("cpu_limit"),
                        mem_limit=inst.get("mem_limit"),
                        shm_size=inst.get("shm_size"),
                    )
                    created.append(session)
                except Exception as e:
                    logger.error(f"Failed to create fixed instance {inst['id']}: {e}")

    return created


def cleanup_orphan_sessions(cfg: dict[str, Any]) -> dict[str, list[str]]:
    from .config import get_fixed_instances_for_user, get_shared_instance_by_id

    result = {"removed_fixed": [], "removed_shared": [], "removed_user_sessions": []}
    all_users = {user["username"] for user in cfg["users"]}

    all_sessions = db.get_all_sessions()

    for session_row in all_sessions:
        if session_row.is_shared:
            shared_config = get_shared_instance_by_id(cfg, session_row.alias)
            if not shared_config:
                delete_session(session_row.session_id, force=True, allow_fixed=True)
                result["removed_shared"].append(session_row.session_id)
            continue

        if session_row.username not in all_users:
            delete_session(session_row.session_id, force=True, allow_fixed=True)
            result["removed_user_sessions"].append(session_row.session_id)
            continue

        if session_row.is_fixed:
            fixed_configs = get_fixed_instances_for_user(cfg, session_row.username)
            config_ids = {inst["id"] for inst in fixed_configs}

            if session_row.alias not in config_ids:
                delete_session(session_row.session_id, force=True, allow_fixed=True)
                result["removed_fixed"].append(session_row.session_id)

    return result


def create_shared_instance(
    cfg: dict[str, Any],
    image_key: str,
    instance_id: str,
    protected: bool = False,
    cpu_limit: float | None = None,
    mem_limit: str | None = None,
    shm_size: str | None = None,
) -> SessionInfo:
    from .config import get_image_config

    image_cfg = get_image_config(cfg, image_key)
    if not image_cfg:
        raise ValueError(f"Image config not found for '{image_key}'")

    session_id = secrets.token_urlsafe(16)

    container = create_session_container(
        cfg, "shared", session_id,
        image_key=image_key,
        image_config=image_cfg,
        persistent_volume=False,
        is_shared=True,
        alias=instance_id,
        cpu_limit_override=cpu_limit,
        mem_limit_override=mem_limit,
        shm_size_override=shm_size,
    )

    container_port = cfg["docker"].get("container_port", 6901)
    time.sleep(2)
    container_ip = get_container_ip(container)

    if container_ip:
        wait_for_ready(container_ip, container_port, timeout=90)

    vnc_password = container.labels.get(f"{LABEL_PREFIX}.vnc_pw")
    now = time.time()

    db_row = db.create_session(
        session_id=session_id,
        container_id=container.id,
        username="shared",
        created_at=now,
        container_ip=container_ip,
        vnc_password=vnc_password,
        image_key=image_key,
        alias=instance_id,
        state="running",
        is_fixed=False,
        is_shared=True,
    )

    if protected:
        db.update_session_protection(session_id, True)

    session_info = _db_to_session_info(db_row)
    session_info.delete_protected = protected

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

    logger.info(f"Created shared instance {session_id} with image {image_key}")
    return session_info


def ensure_shared_instances(cfg: dict[str, Any]) -> list[SessionInfo]:
    created = []
    shared_configs = cfg.get("shared_instances", [])
    config_ids = {inst["id"] for inst in shared_configs}
    config_by_id = {inst["id"]: inst for inst in shared_configs}

    all_sessions = db.get_all_sessions()
    shared_sessions = [s for s in all_sessions if s.is_shared]
    existing_ids_with_containers = set()
    preserved_protection = {}
    needs_recreate = set()

    for shared_session in shared_sessions:
        if shared_session.state == "terminated":
            if shared_session.alias in config_ids:
                logger.info(f"Removing terminated DB record for shared instance '{shared_session.alias}'")
                db.delete_session(shared_session.session_id)
            continue

        # Skip sessions that are currently restarting
        if shared_session.state == "restarting":
            existing_ids_with_containers.add(shared_session.alias)
            continue

        container = get_container_by_session_id(shared_session.session_id)
        if container is not None:
            inst = config_by_id.get(shared_session.alias)
            if inst and _resource_limits_changed(
                container, cfg, "shared",
                inst.get("cpu_limit"), inst.get("mem_limit"), inst.get("shm_size")
            ):
                logger.info(f"Resource limits changed for shared instance '{shared_session.alias}', recreating")
                preserved_protection[shared_session.alias] = shared_session.delete_protected
                delete_session(shared_session.session_id, force=True, allow_fixed=True)
                needs_recreate.add(shared_session.alias)
            else:
                existing_ids_with_containers.add(shared_session.alias)
                if inst:
                    config_protected = inst.get("protected", False)
                    if shared_session.delete_protected != config_protected:
                        db.update_session_protection(shared_session.session_id, config_protected)
                        logger.info(f"Synced protection status for shared instance '{shared_session.alias}' to {config_protected}")
        else:
            preserved_protection[shared_session.alias] = shared_session.delete_protected
            logger.info(f"Removing stale DB record for shared instance '{shared_session.alias}' (container missing, preserving protection={shared_session.delete_protected})")
            db.delete_session(shared_session.session_id)

    for inst in shared_configs:
        if inst["id"] not in existing_ids_with_containers:
            protection = preserved_protection.get(inst["id"], inst.get("protected", False))
            try:
                session = create_shared_instance(
                    cfg,
                    image_key=inst["image"],
                    instance_id=inst["id"],
                    protected=protection,
                    cpu_limit=inst.get("cpu_limit"),
                    mem_limit=inst.get("mem_limit"),
                    shm_size=inst.get("shm_size"),
                )
                created.append(session)
            except Exception as e:
                logger.error(f"Failed to create shared instance {inst['id']}: {e}")

    return created


def get_shared_sessions_for_user(cfg: dict[str, Any], username: str) -> list[SessionInfo]:
    from .config import is_user_allowed_for_shared_instance

    all_sessions = db.get_all_sessions()
    shared_sessions = []

    for session_row in all_sessions:
        if session_row.is_shared:
            if is_user_allowed_for_shared_instance(cfg, session_row.alias, username):
                shared_sessions.append(_db_to_session_info(session_row))

    return shared_sessions


def can_user_manage_shared_session(cfg: dict[str, Any], session_id: str, username: str) -> bool:
    from .config import is_user_admin_for_shared_instance

    session = get_session(session_id)
    if not session or not session.is_shared:
        return False

    return is_user_admin_for_shared_instance(cfg, session.alias, username)

import docker
import secrets
import socket
import time
import logging
from datetime import datetime
from docker.models.containers import Container
from typing import Any

logger = logging.getLogger(__name__)

LABEL_PREFIX = "mini-kasm"


def get_docker_client() -> docker.DockerClient:
    return docker.from_env()


def parse_container_created(container: Container) -> float:
    created = container.attrs.get("Created")
    if not created:
        return time.time()
    if isinstance(created, (int, float)):
        return float(created)
    try:
        dt = datetime.fromisoformat(created.replace("Z", "+00:00"))
        return dt.timestamp()
    except (ValueError, AttributeError):
        return time.time()


def wait_for_ready(ip: str, port: int, timeout: int = 60) -> bool:
    start = time.time()
    while time.time() - start < timeout:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex((ip, port))
            sock.close()
            if result == 0:
                logger.info(f"Container {ip}:{port} is ready")
                return True
        except Exception:
            pass
        time.sleep(1)
    logger.warning(f"Container {ip}:{port} not ready after {timeout}s")
    return False


def image_exists(image_name: str) -> bool:
    client = get_docker_client()
    try:
        client.images.get(image_name)
        return True
    except docker.errors.ImageNotFound:
        return False


def pull_image(image_name: str, progress_callback=None) -> bool:
    client = get_docker_client()
    try:
        logger.info(f"Pulling image {image_name}...")

        for line in client.api.pull(image_name, stream=True, decode=True):
            if progress_callback:
                progress_callback(line)

            status = line.get("status", "")
            progress = line.get("progress", "")
            layer_id = line.get("id", "")

            if layer_id and progress:
                logger.debug(f"{layer_id}: {status} {progress}")
            elif status:
                logger.info(f"Pull: {status}")

        logger.info(f"Successfully pulled {image_name}")
        return True
    except Exception as e:
        logger.error(f"Failed to pull image {image_name}: {e}")
        return False


def create_session_container(
    cfg: dict[str, Any],
    username: str,
    session_id: str,
    image_key: str | None = None,
    image_config: dict[str, Any] | None = None,
    persistent_volume: bool = False,
    is_fixed: bool = False,
    is_shared: bool = False,
    alias: str | None = None,
    cpu_limit_override: float | None = None,
    mem_limit_override: str | None = None,
    shm_size_override: str | None = None,
) -> Container:
    client = get_docker_client()
    docker_cfg = cfg["docker"]
    user_cfg = _get_user_cfg(cfg, username)

    # Determine which image to use
    if image_config:
        session_image = image_config.get("image", docker_cfg["session_image"])
    else:
        session_image = docker_cfg["session_image"]

    env = dict(docker_cfg.get("env") or {})
    env["VNC_PW"] = secrets.token_urlsafe(12)

    resolution = None
    if image_config:
        resolution = image_config.get("resolution")
    if not resolution:
        resolution = docker_cfg.get("resolution")
    if resolution:
        env["VNC_RESOLUTION"] = resolution

    cpu_limit = cpu_limit_override if cpu_limit_override is not None else user_cfg.get("cpu_limit", 1.0)
    mem_limit = mem_limit_override if mem_limit_override is not None else user_cfg.get("mem_limit", "512m")
    shm_size = shm_size_override if shm_size_override is not None else user_cfg.get("shm_size", docker_cfg.get("shm_size", "512m"))

    labels = {
        f"{LABEL_PREFIX}.managed": "true",
        f"{LABEL_PREFIX}.username": username,
        f"{LABEL_PREFIX}.session_id": session_id,
        f"{LABEL_PREFIX}.vnc_pw": env["VNC_PW"],
        f"{LABEL_PREFIX}.is_fixed": str(is_fixed).lower(),
        f"{LABEL_PREFIX}.is_shared": str(is_shared).lower(),
        f"{LABEL_PREFIX}.cpu_limit": str(cpu_limit),
        f"{LABEL_PREFIX}.mem_limit": str(mem_limit),
        f"{LABEL_PREFIX}.shm_size": str(shm_size),
    }

    if image_key:
        labels[f"{LABEL_PREFIX}.image_key"] = image_key

    if alias:
        labels[f"{LABEL_PREFIX}.alias"] = alias

    container_name = f"kasm-session-{session_id}"
    container_port = docker_cfg.get("container_port", 6901)
    publish_ports = docker_cfg.get("publish_ports", False)

    run_kwargs = dict(
        image=session_image,
        name=container_name,
        detach=True,
        environment=env,
        labels=labels,
        network=docker_cfg["network"],
        cpu_period=100000,
        cpu_quota=int(cpu_limit * 100000),
        mem_limit=mem_limit,
        shm_size=shm_size,
        restart_policy={"Name": "unless-stopped"},
    )

    if publish_ports:
        run_kwargs["ports"] = {f"{container_port}/tcp": None}

    if "session_command" in docker_cfg:
        run_kwargs["command"] = docker_cfg["session_command"]

    # Setup volume mounts
    volumes = {}

    # Image-specific volumes
    if image_config and "volumes" in image_config:
        for vol_cfg in image_config["volumes"]:
            mount_path = vol_cfg["path"]
            suffix = vol_cfg.get("suffix", mount_path.replace("/", "-").strip("-"))
            volume_name = f"kasm-{username}-{suffix}"
            _ensure_volume_exists(client, volume_name)
            volumes[volume_name] = {"bind": mount_path, "mode": "rw"}
            logger.debug(f"Mounting image volume {volume_name} at {mount_path}")

    # User persistent volume
    if persistent_volume:
        user_volume_path = docker_cfg.get("user_volume_path", "/home/kasm-user/data")
        user_volume_name = f"kasm-{username}-data"
        _ensure_volume_exists(client, user_volume_name)
        volumes[user_volume_name] = {"bind": user_volume_path, "mode": "rw"}
        logger.debug(f"Mounting user volume {user_volume_name} at {user_volume_path}")

    if volumes:
        run_kwargs["volumes"] = volumes

    if image_config:
        cap_drop = image_config.get("cap_drop", ["ALL"])
        cap_add = image_config.get("cap_add", ["CHOWN", "SETUID", "SETGID", "NET_RAW"])
    else:
        cap_drop = ["ALL"]
        cap_add = ["CHOWN", "SETUID", "SETGID", "NET_RAW"]

    if cap_drop:
        run_kwargs["cap_drop"] = cap_drop
    if cap_add:
        run_kwargs["cap_add"] = cap_add

    container = client.containers.run(**run_kwargs)
    logger.info(f"Created container {container_name} for user {username} with image {session_image}")
    return container


def _ensure_volume_exists(client: docker.DockerClient, volume_name: str) -> None:
    try:
        client.volumes.get(volume_name)
    except docker.errors.NotFound:
        client.volumes.create(name=volume_name)
        logger.info(f"Created Docker volume: {volume_name}")


def get_container_by_session_id(session_id: str) -> Container | None:
    client = get_docker_client()
    filters = {
        "label": [
            f"{LABEL_PREFIX}.managed=true",
            f"{LABEL_PREFIX}.session_id={session_id}",
        ]
    }
    containers = client.containers.list(filters=filters, all=True)
    return containers[0] if containers else None


def get_containers_for_user(username: str) -> list[Container]:
    client = get_docker_client()
    filters = {
        "label": [
            f"{LABEL_PREFIX}.managed=true",
            f"{LABEL_PREFIX}.username={username}",
        ]
    }
    return client.containers.list(filters=filters, all=True)


def get_all_managed_containers() -> list[Container]:
    client = get_docker_client()
    filters = {"label": [f"{LABEL_PREFIX}.managed=true"]}
    return client.containers.list(filters=filters, all=True)


def get_container_ip(container: Container) -> str | None:
    container.reload()
    networks = container.attrs.get("NetworkSettings", {}).get("Networks", {})
    for net_name, net_info in networks.items():
        ip = net_info.get("IPAddress")
        if ip:
            return ip
    return None


def get_published_port(container: Container, container_port: int = 6901) -> int | None:
    container.reload()
    ports = container.attrs.get("NetworkSettings", {}).get("Ports", {})
    port_key = f"{container_port}/tcp"
    if port_key in ports and ports[port_key]:
        return int(ports[port_key][0]["HostPort"])
    return None


def stop_container(container: Container) -> None:
    try:
        container.stop(timeout=10)
        container.remove()
        logger.info(f"Stopped and removed container {container.name}")
    except docker.errors.NotFound:
        pass
    except Exception as e:
        logger.error(f"Error stopping container {container.name}: {e}")


def is_container_running(container: Container) -> bool:
    try:
        container.reload()
        return container.status == "running"
    except docker.errors.NotFound:
        return False


def is_container_paused(container: Container) -> bool:
    try:
        container.reload()
        return container.status == "paused"
    except docker.errors.NotFound:
        return False


def pause_container(container: Container) -> bool:
    try:
        container.reload()
        if container.status == "running":
            container.pause()
            logger.info(f"Paused container {container.name}")
            return True
        return False
    except docker.errors.NotFound:
        return False
    except Exception as e:
        logger.error(f"Error pausing container {container.name}: {e}")
        return False


def unpause_container(container: Container) -> bool:
    try:
        container.reload()
        if container.status == "paused":
            container.unpause()
            logger.info(f"Unpaused container {container.name}")
            return True
        return False
    except docker.errors.NotFound:
        return False
    except Exception as e:
        logger.error(f"Error unpausing container {container.name}: {e}")
        return False


def get_container_stats(container: Container) -> dict[str, float]:
    try:
        stats = container.stats(stream=False)

        cpu_delta = stats["cpu_stats"]["cpu_usage"]["total_usage"] - \
                    stats["precpu_stats"]["cpu_usage"]["total_usage"]
        system_delta = stats["cpu_stats"]["system_cpu_usage"] - \
                       stats["precpu_stats"]["system_cpu_usage"]
        num_cpus = stats["cpu_stats"]["online_cpus"]

        cpu_percent = 0.0
        if system_delta > 0 and cpu_delta > 0:
            cpu_percent = (cpu_delta / system_delta) * num_cpus * 100.0

        cpu_quota = container.attrs["HostConfig"]["CpuQuota"]
        cpu_period = container.attrs["HostConfig"]["CpuPeriod"]
        cpu_cores = cpu_quota / cpu_period if cpu_period > 0 and cpu_quota > 0 else 0

        mem_usage = stats["memory_stats"].get("usage", 0)
        mem_limit = stats["memory_stats"].get("limit", 1)
        mem_percent = (mem_usage / mem_limit) * 100.0 if mem_limit > 0 else 0.0

        return {
            "cpu_percent": round(cpu_percent, 1),
            "cpu_cores": cpu_cores,
            "mem_percent": round(mem_percent, 1),
            "mem_usage_mb": round(mem_usage / (1024 * 1024), 1),
            "mem_limit_mb": round(mem_limit / (1024 * 1024), 1),
        }
    except Exception as e:
        logger.error(f"Error getting container stats: {e}")
        return {"cpu_percent": 0.0, "cpu_cores": 0, "mem_percent": 0.0, "mem_usage_mb": 0.0, "mem_limit_mb": 0.0}


def _get_user_cfg(cfg: dict[str, Any], username: str) -> dict[str, Any]:
    for user in cfg["users"]:
        if user["username"] == username:
            return user
    return {}

import yaml
from typing import Any


def load_config(path: str) -> dict[str, Any]:
    with open(path, "r") as f:
        cfg = yaml.safe_load(f)

    required_sections = ["server", "docker", "users"]
    for section in required_sections:
        if section not in cfg:
            raise ValueError(f"Missing required config section: {section}")

    server = cfg["server"]
    server.setdefault("secret_key", "change-me")
    server.setdefault("session_path_prefix", "/u")
    server.setdefault("idle_timeout_seconds", 600)
    server.setdefault("max_sessions_total", 50)

    docker = cfg["docker"]
    docker.setdefault("network", "spal_kasm_net")
    docker.setdefault("container_port", 6901)
    docker.setdefault("shm_size", "512m")
    docker.setdefault("env", {})
    docker.setdefault("user_volume_path", "/home/kasm-user/data")

    if "allowed_images" not in docker:
        if "session_image" not in docker:
            raise ValueError("docker.session_image or docker.allowed_images is required")
        docker["allowed_images"] = {
            "default": {
                "name": "Default",
                "image": docker["session_image"],
                "default": True,
            }
        }
    else:
        _validate_allowed_images(docker["allowed_images"])
        if "session_image" not in docker:
            for key, img in docker["allowed_images"].items():
                if img.get("default"):
                    docker["session_image"] = img["image"]
                    break
            else:
                first_key = next(iter(docker["allowed_images"]))
                docker["session_image"] = docker["allowed_images"][first_key]["image"]

    if not cfg["users"]:
        raise ValueError("At least one user must be configured")

    for user in cfg["users"]:
        if "username" not in user or "password_hash_bcrypt" not in user:
            raise ValueError("Each user must have username and password_hash_bcrypt")
        user.setdefault("max_sessions", 1)
        user.setdefault("cpu_limit", 1.0)
        user.setdefault("mem_limit", "1024m")
        user.setdefault("shm_size", "512m")
        user.setdefault("persistent_volume", False)

    return cfg


def _validate_allowed_images(allowed_images: dict[str, Any]) -> None:
    if not allowed_images:
        raise ValueError("docker.allowed_images must contain at least one image")

    has_default = False
    for key, img_cfg in allowed_images.items():
        if not isinstance(img_cfg, dict):
            raise ValueError(f"Image config for '{key}' must be a dictionary")
        if "image" not in img_cfg:
            raise ValueError(f"Image config for '{key}' must have 'image' field")
        img_cfg.setdefault("name", key)
        if img_cfg.get("default"):
            has_default = True

    if not has_default:
        first_key = next(iter(allowed_images))
        allowed_images[first_key]["default"] = True


def get_user_config(cfg: dict[str, Any], username: str) -> dict[str, Any] | None:
    for user in cfg["users"]:
        if user["username"] == username:
            return user
    return None


def get_allowed_images_for_user(cfg: dict[str, Any], username: str) -> dict[str, Any]:
    all_images = cfg["docker"].get("allowed_images", {})
    user_cfg = get_user_config(cfg, username)

    if not user_cfg:
        return {}

    user_allowed = user_cfg.get("allowed_images")
    if user_allowed is None:
        return all_images

    return {key: all_images[key] for key in user_allowed if key in all_images}


def get_image_config(cfg: dict[str, Any], image_key: str) -> dict[str, Any] | None:
    return cfg["docker"].get("allowed_images", {}).get(image_key)


def get_default_image_for_user(cfg: dict[str, Any], username: str) -> str | None:
    user_cfg = get_user_config(cfg, username)
    if not user_cfg:
        return None

    user_default = user_cfg.get("default_image")
    allowed = get_allowed_images_for_user(cfg, username)

    if user_default and user_default in allowed:
        return user_default

    for key, img_cfg in allowed.items():
        if img_cfg.get("default"):
            return key

    return next(iter(allowed), None)

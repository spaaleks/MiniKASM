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
    server.setdefault("login_session_timeout_hours", 24)

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
        user.setdefault("enable", True)
        user.setdefault("max_sessions", 1)
        user.setdefault("cpu_limit", 1.0)
        user.setdefault("mem_limit", "1024m")
        user.setdefault("shm_size", "512m")
        user.setdefault("persistent_volume", False)

    cfg.setdefault("fixed_instances", [])
    _validate_fixed_instances(cfg)

    cfg.setdefault("shared_instances", [])
    _validate_shared_instances(cfg)

    return cfg


def _validate_fixed_instances(cfg: dict[str, Any]) -> None:
    fixed_instances = cfg.get("fixed_instances", [])
    allowed_images = cfg["docker"].get("allowed_images", {})
    usernames = {user["username"] for user in cfg["users"]}
    seen_ids = set()

    for i, instance in enumerate(fixed_instances):
        if not isinstance(instance, dict):
            raise ValueError(f"fixed_instances[{i}] must be a dictionary")
        if "username" not in instance:
            raise ValueError(f"fixed_instances[{i}] must have 'username' field")
        if "image" not in instance:
            raise ValueError(f"fixed_instances[{i}] must have 'image' field")

        if "id" not in instance and "title" not in instance:
            raise ValueError(f"fixed_instances[{i}] must have 'id' field")
        if "id" not in instance:
            instance["id"] = instance["title"]
        instance.setdefault("name", instance.get("title", instance["id"]))

        inst_id = instance["id"]
        if inst_id in seen_ids:
            raise ValueError(f"fixed_instances[{i}]: duplicate id '{inst_id}'")
        seen_ids.add(inst_id)

        if instance["username"] not in usernames:
            raise ValueError(f"fixed_instances[{i}]: user '{instance['username']}' not found")
        if instance["image"] not in allowed_images:
            raise ValueError(f"fixed_instances[{i}]: image '{instance['image']}' not found")

        instance.setdefault("protected", False)
        instance.setdefault("cpu_limit", None)
        instance.setdefault("mem_limit", None)
        instance.setdefault("shm_size", None)


def _validate_shared_instances(cfg: dict[str, Any]) -> None:
    shared_instances = cfg.get("shared_instances", [])
    allowed_images = cfg["docker"].get("allowed_images", {})
    usernames = {user["username"] for user in cfg["users"]}
    seen_ids = set()

    for i, instance in enumerate(shared_instances):
        if not isinstance(instance, dict):
            raise ValueError(f"shared_instances[{i}] must be a dictionary")
        if "image" not in instance:
            raise ValueError(f"shared_instances[{i}] must have 'image' field")
        if "allowed_users" not in instance:
            raise ValueError(f"shared_instances[{i}] must have 'allowed_users' field")

        if "id" not in instance and "title" not in instance:
            raise ValueError(f"shared_instances[{i}] must have 'id' field")
        if "id" not in instance:
            instance["id"] = instance["title"]
        instance.setdefault("name", instance.get("title", instance["id"]))

        inst_id = instance["id"]
        if inst_id in seen_ids:
            raise ValueError(f"shared_instances[{i}]: duplicate id '{inst_id}'")
        seen_ids.add(inst_id)

        if instance["image"] not in allowed_images:
            raise ValueError(f"shared_instances[{i}]: image '{instance['image']}' not found")

        for user in instance["allowed_users"]:
            if user not in usernames:
                raise ValueError(f"shared_instances[{i}]: user '{user}' not found")

        instance.setdefault("admin_users", [])
        for user in instance["admin_users"]:
            if user not in usernames:
                raise ValueError(f"shared_instances[{i}]: admin user '{user}' not found")

        instance.setdefault("protected", False)
        instance.setdefault("cpu_limit", None)
        instance.setdefault("mem_limit", None)
        instance.setdefault("shm_size", None)


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
        img_cfg.setdefault("cap_drop", ["ALL"])
        img_cfg.setdefault("cap_add", ["CHOWN", "SETUID", "SETGID", "NET_RAW"])
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

    if isinstance(user_allowed, list):
        return {key: all_images[key] for key in user_allowed if key in all_images}
    elif isinstance(user_allowed, dict):
        return {key: all_images[key] for key in user_allowed if key in all_images}

    return {}


def get_image_limit_for_user(cfg: dict[str, Any], username: str, image_key: str) -> int | None:
    user_cfg = get_user_config(cfg, username)
    if not user_cfg:
        return None

    user_allowed = user_cfg.get("allowed_images")
    if user_allowed is None:
        return None

    if isinstance(user_allowed, dict):
        image_limits = user_allowed.get(image_key)
        if isinstance(image_limits, dict):
            return image_limits.get("max_sessions")

    return None


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


def get_fixed_instances_for_user(cfg: dict[str, Any], username: str) -> list[dict[str, Any]]:
    return [
        inst for inst in cfg.get("fixed_instances", [])
        if inst["username"] == username
    ]


def get_fixed_instance_by_id(cfg: dict[str, Any], instance_id: str) -> dict[str, Any] | None:
    for inst in cfg.get("fixed_instances", []):
        if inst["id"] == instance_id:
            return inst
    return None


def get_fixed_instance_by_title(cfg: dict[str, Any], username: str, title: str) -> dict[str, Any] | None:
    for inst in cfg.get("fixed_instances", []):
        if inst["username"] == username and inst.get("title") == title:
            return inst
    return None


def get_shared_instances_for_user(cfg: dict[str, Any], username: str) -> list[dict[str, Any]]:
    return [
        inst for inst in cfg.get("shared_instances", [])
        if username in inst.get("allowed_users", [])
    ]


def get_shared_instance_by_id(cfg: dict[str, Any], instance_id: str) -> dict[str, Any] | None:
    for inst in cfg.get("shared_instances", []):
        if inst["id"] == instance_id:
            return inst
    return None


def get_shared_instance_by_title(cfg: dict[str, Any], title: str) -> dict[str, Any] | None:
    for inst in cfg.get("shared_instances", []):
        if inst.get("title") == title:
            return inst
    return None


def is_user_allowed_for_shared_instance(cfg: dict[str, Any], instance_id: str, username: str) -> bool:
    inst = get_shared_instance_by_id(cfg, instance_id)
    if inst:
        return username in inst.get("allowed_users", [])
    return False


def is_user_admin_for_shared_instance(cfg: dict[str, Any], instance_id: str, username: str) -> bool:
    inst = get_shared_instance_by_id(cfg, instance_id)
    if inst:
        return username in inst.get("admin_users", [])
    return False


def get_instance_display_name(cfg: dict[str, Any], instance_id: str, is_shared: bool = False) -> str:
    if is_shared:
        inst = get_shared_instance_by_id(cfg, instance_id)
    else:
        inst = get_fixed_instance_by_id(cfg, instance_id)
    if inst:
        return inst.get("name", instance_id)
    return instance_id


def get_all_instance_display_names(cfg: dict[str, Any]) -> dict[str, str]:
    names = {}
    for inst in cfg.get("fixed_instances", []):
        names[inst["id"]] = inst.get("name", inst["id"])
    for inst in cfg.get("shared_instances", []):
        names[inst["id"]] = inst.get("name", inst["id"])
    return names


def is_user_enabled(cfg: dict[str, Any], username: str) -> bool:
    user_cfg = get_user_config(cfg, username)
    if not user_cfg:
        return False
    return user_cfg.get("enable", True)


def get_disabled_users(cfg: dict[str, Any]) -> list[str]:
    return [user["username"] for user in cfg["users"] if not user.get("enable", True)]

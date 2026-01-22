#!/usr/bin/env python3
import os
import sys
import argparse
import logging

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


def main():
    parser = argparse.ArgumentParser(
        description="MiniKASM cleanup utility for orphan sessions"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would be deleted without actually deleting"
    )
    args = parser.parse_args()

    from .config import load_config
    from . import database as db

    cfg_path = os.environ.get("CONFIG_PATH", "/config/users.yaml")
    cfg = load_config(cfg_path)

    db.init_db()

    if args.dry_run:
        logger.info("DRY RUN - No changes will be made")
        from .config import get_fixed_instances_for_user, get_shared_instance_by_title

        all_users = {user["username"] for user in cfg["users"]}
        all_sessions = db.get_all_sessions()

        orphans = {"fixed": [], "shared": [], "user_sessions": []}

        for session_row in all_sessions:
            if session_row.is_shared:
                shared_config = get_shared_instance_by_title(cfg, session_row.alias)
                if not shared_config:
                    orphans["shared"].append((session_row.session_id, session_row.alias))
                continue

            if session_row.username not in all_users:
                orphans["user_sessions"].append((session_row.session_id, session_row.username))
                continue

            if session_row.is_fixed:
                fixed_configs = get_fixed_instances_for_user(cfg, session_row.username)
                config_titles = {inst["title"] for inst in fixed_configs}
                if session_row.alias not in config_titles:
                    orphans["fixed"].append((session_row.session_id, session_row.alias, session_row.username))

        if any(orphans.values()):
            if orphans["fixed"]:
                logger.info("Orphan fixed instances to remove:")
                for sid, alias, user in orphans["fixed"]:
                    logger.info(f"  - {sid} ({alias}) for user {user}")

            if orphans["shared"]:
                logger.info("Orphan shared instances to remove:")
                for sid, alias in orphans["shared"]:
                    logger.info(f"  - {sid} ({alias})")

            if orphans["user_sessions"]:
                logger.info("Sessions for removed users to delete:")
                for sid, user in orphans["user_sessions"]:
                    logger.info(f"  - {sid} (user: {user})")
        else:
            logger.info("No orphan sessions found")
    else:
        from .sessions import cleanup_orphan_sessions

        logger.info("Running cleanup...")
        result = cleanup_orphan_sessions(cfg)

        total = len(result["removed_fixed"]) + len(result["removed_shared"]) + len(result["removed_user_sessions"])

        if total > 0:
            if result["removed_fixed"]:
                logger.info(f"Removed {len(result['removed_fixed'])} orphan fixed instances:")
                for sid in result["removed_fixed"]:
                    logger.info(f"  - {sid}")

            if result["removed_shared"]:
                logger.info(f"Removed {len(result['removed_shared'])} orphan shared instances:")
                for sid in result["removed_shared"]:
                    logger.info(f"  - {sid}")

            if result["removed_user_sessions"]:
                logger.info(f"Removed {len(result['removed_user_sessions'])} sessions for deleted users:")
                for sid in result["removed_user_sessions"]:
                    logger.info(f"  - {sid}")

            logger.info(f"Total: {total} sessions removed")
        else:
            logger.info("No orphan sessions found")


if __name__ == "__main__":
    main()

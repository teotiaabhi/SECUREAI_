import os
import logging
logger = logging.getLogger("repo_ingestion.zip_guard")

def validate_zip_entry(entry_name):
    if entry_name.startswith("/") or entry_name.startswith("\\"):
        logger.warning("[ZIPGUARD] absolute path rejected: %s", entry_name)
        return False
    if ".." in entry_name.split("/"):
        logger.warning("[ZIPGUARD] path traversal rejected: %s", entry_name)
        return False
    return True

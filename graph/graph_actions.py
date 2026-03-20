import requests
import logging

from graph.graph_auth import get_graph_token
from graph.graph_config import GRAPH_BASE_URL

logger = logging.getLogger("graph_actions")


# ==========================================================
# 📂 GET OR CREATE FOLDER
# ==========================================================

def get_or_create_folder(user_id: str, folder_name: str):
    """
    Check if folder exists, else create it
    """

    token = get_graph_token()

    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }

    # Step 1: Get existing folders
    url = f"{GRAPH_BASE_URL}/users/{user_id}/mailFolders"

    response = requests.get(url, headers=headers)

    if response.status_code != 200:
        logger.error(f"❌ Failed to fetch folders: {response.text}")
        return None

    folders = response.json().get("value", [])

    # Step 2: Check if folder exists
    for folder in folders:
        if folder.get("displayName").lower() == folder_name.lower():
            return folder.get("id")

    # Step 3: Create folder if not exists
    create_url = f"{GRAPH_BASE_URL}/users/{user_id}/mailFolders"

    data = {
        "displayName": folder_name
    }

    create_response = requests.post(create_url, headers=headers, json=data)

    if create_response.status_code not in [200, 201]:
        logger.error(f"❌ Failed to create folder: {create_response.text}")
        return None

    folder_id = create_response.json().get("id")
    return folder_id


# ==========================================================
# 📦 MOVE EMAIL
# ==========================================================

def move_email(user_id: str, message_id: str, folder_id: str):
    """
    Move email to specific folder
    """

    token = get_graph_token()

    url = f"{GRAPH_BASE_URL}/users/{user_id}/messages/{message_id}/move"

    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }

    data = {
        "destinationId": folder_id
    }

    response = requests.post(url, headers=headers, json=data)

    if response.status_code not in [200, 201]:
        logger.error(f"❌ Failed to move email: {response.text}")
        return False

    logger.info(f"✅ Email moved successfully")
    return True


# ==========================================================
# 🚨 MOVE TO PHISHING
# ==========================================================

def move_to_phishing(user_id: str, message_id: str):
    """
    Move email to Phishing folder
    """

    folder_id = get_or_create_folder(user_id, "Phishing")

    if not folder_id:
        return False

    return move_email(user_id, message_id, folder_id)


# ==========================================================
# ⚠️ MOVE TO SUSPICIOUS
# ==========================================================

def move_to_suspicious(user_id: str, message_id: str):
    """
    Move email to Suspicious folder
    """

    folder_id = get_or_create_folder(user_id, "Suspicious")

    if not folder_id:
        return False

    return move_email(user_id, message_id, folder_id)
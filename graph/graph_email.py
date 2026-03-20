import requests
import logging

from graph.graph_auth import get_graph_token
from graph.graph_config import GRAPH_BASE_URL

logger = logging.getLogger("graph_email")


# ==========================================================
# 📥 FETCH EMAIL BY MESSAGE ID
# ==========================================================

def fetch_email_by_id(user_id: str, message_id: str):
    """
    Fetch full email details from Microsoft Graph
    """

    try:
        token = get_graph_token()

        url = f"{GRAPH_BASE_URL}/users/{user_id}/messages/{message_id}"

        headers = {
            "Authorization": f"Bearer {token}"
        }

        response = requests.get(url, headers=headers)

        if response.status_code != 200:
            logger.error(f"❌ Failed to fetch email: {response.status_code} {response.text}")
            return None

        data = response.json()

        return data

    except Exception as e:
        logger.error(f"❌ Exception in fetch_email_by_id: {str(e)}")
        return None


# ==========================================================
# 📥 OPTIONAL: FETCH WITH SELECT (OPTIMIZED)
# ==========================================================

def fetch_email_minimal(user_id: str, message_id: str):
    """
    Fetch only required fields (faster + optimized)
    """

    try:
        token = get_graph_token()

        url = f"{GRAPH_BASE_URL}/users/{user_id}/messages/{message_id}"

        params = {
            "$select": "subject,body,from"
        }

        headers = {
            "Authorization": f"Bearer {token}"
        }

        response = requests.get(url, headers=headers, params=params)

        if response.status_code != 200:
            logger.error(f"❌ Failed to fetch minimal email: {response.status_code} {response.text}")
            return None

        return response.json()

    except Exception as e:
        logger.error(f"❌ Exception in fetch_email_minimal: {str(e)}")
        return None
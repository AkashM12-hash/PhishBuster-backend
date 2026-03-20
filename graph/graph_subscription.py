import requests
import logging
from datetime import datetime, timedelta

from graph.graph_auth import get_graph_token
from graph.graph_config import GRAPH_BASE_URL, WEBHOOK_URL

logger = logging.getLogger("graph_subscription")

# In production → store in DB
subscription_data = {
    "id": None,
    "expiration": None
}


# ==========================================================
# 🔔 CREATE SUBSCRIPTION
# ==========================================================

def create_subscription(user_id: str):
    """
    Create Graph webhook subscription
    """

    try:
        token = get_graph_token()

        url = f"{GRAPH_BASE_URL}/subscriptions"

        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json"
        }

        expiration_time = (datetime.utcnow() + timedelta(minutes=4000)).isoformat() + "Z"

        data = {
            "changeType": "created",
            "notificationUrl": WEBHOOK_URL,
            "resource": f"/users/{user_id}/mailFolders('Inbox')/messages",
            "expirationDateTime": expiration_time,
            "clientState": "phishbuster-secret"
        }

        response = requests.post(url, headers=headers, json=data)

        if response.status_code not in [200, 201]:
            logger.error(f"❌ Subscription failed: {response.text}")
            return None

        result = response.json()

        subscription_data["id"] = result.get("id")
        subscription_data["expiration"] = result.get("expirationDateTime")

        logger.info(f"✅ Subscription created: {subscription_data}")

        return result

    except Exception as e:
        logger.error(f"❌ Exception in create_subscription: {str(e)}")
        return None


# ==========================================================
# 🔁 RENEW SUBSCRIPTION
# ==========================================================

def renew_subscription():
    """
    Renew existing subscription before expiry
    """

    if not subscription_data["id"]:
        logger.warning("⚠️ No subscription found to renew")
        return None

    try:
        token = get_graph_token()

        url = f"{GRAPH_BASE_URL}/subscriptions/{subscription_data['id']}"

        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json"
        }

        new_expiration = (datetime.utcnow() + timedelta(minutes=4000)).isoformat() + "Z"

        data = {
            "expirationDateTime": new_expiration
        }

        response = requests.patch(url, headers=headers, json=data)

        if response.status_code != 200:
            logger.error(f"❌ Renewal failed: {response.text}")
            return None

        result = response.json()

        subscription_data["expiration"] = result.get("expirationDateTime")

        logger.info(f"🔁 Subscription renewed")

        return result

    except Exception as e:
        logger.error(f"❌ Exception in renew_subscription: {str(e)}")
        return None


# ==========================================================
# ⏰ CHECK IF RENEWAL NEEDED
# ==========================================================

def is_renewal_needed():
    """
    Check if subscription is near expiry
    """

    if not subscription_data["expiration"]:
        return True

    expiration_time = datetime.fromisoformat(subscription_data["expiration"].replace("Z", ""))
    now = datetime.utcnow()

    # Renew if less than 1 hour remaining
    return (expiration_time - now) < timedelta(minutes=60)


# ==========================================================
# 🔄 AUTO MANAGE SUBSCRIPTION
# ==========================================================

def ensure_subscription(user_id: str):
    """
    Ensure subscription exists and is active
    """

    if not subscription_data["id"]:
        logger.info("📡 Creating new subscription...")
        return create_subscription(user_id)

    if is_renewal_needed():
        logger.info("🔁 Renewing subscription...")
        return renew_subscription()

    logger.info("✅ Subscription is active")
    return None
from fastapi import APIRouter, Request, Response
from fastapi.responses import PlainTextResponse
import json
import logging

from graph.graph_config import GRAPH_ENABLED
from graph.graph_email import fetch_email_by_id
from graph.graph_actions import move_to_phishing, move_to_suspicious

# Import your existing analysis logic
from main import analyze_outlook_email, OutlookEmailRequest

router = APIRouter()

logger = logging.getLogger("graph_webhook")


# ==========================================================
# 🔔 WEBHOOK ENDPOINT
# ==========================================================

@router.api_route("/webhook", methods=["GET", "POST"])
async def graph_webhook(request: Request):
    
    # ==========================================
    # ✅ 1. VALIDATION TOKEN HANDLING
    # ==========================================
    validation_token = request.query_params.get("validationToken")

    if validation_token:
        # Graph expects plain text response
        return PlainTextResponse(content=validation_token, status_code=200)

    # ==========================================
    # ❌ If Graph disabled → ignore safely
    # ==========================================
    if not GRAPH_ENABLED:
        return {"status": "Graph disabled"}

    try:
        body = await request.json()
        logger.info(f"📩 Webhook received: {json.dumps(body)}")

        # ==========================================
        # 🔔 2. PROCESS NOTIFICATIONS
        # ==========================================
        notifications = body.get("value", [])

        for notification in notifications:

            resource = notification.get("resource", "")

            # Example:
            # users/{userId}/messages/{messageId}
            parts = resource.split("/")

            if len(parts) < 4:
                continue

            user_id = parts[1]
            message_id = parts[3]

            logger.info(f"📨 Processing email: {message_id} for user: {user_id}")

            # ==========================================
            # 📥 3. FETCH EMAIL FROM GRAPH
            # ==========================================
            email_data = fetch_email_by_id(user_id, message_id)

            if not email_data:
                continue

            # Extract fields
            subject = email_data.get("subject", "")
            body = email_data.get("body", {}).get("content", "")
            sender = email_data.get("from", {}).get("emailAddress", {}).get("address", "")

            # ==========================================
            # 🧠 4. CALL YOUR EXISTING ANALYZER
            # ==========================================
            request_obj = OutlookEmailRequest(
                senderName="",
                senderEmail=sender,
                userEmail=user_id,
                subject=subject,
                body=body,
                messageId=message_id
            )

            result = analyze_outlook_email(request_obj)

            category = result.get("category")

            logger.info(f"🧠 Result: {category}")

            # ==========================================
            # ⚡ 5. TAKE ACTION
            # ==========================================
            if category == "PHISHING":
                move_to_phishing(user_id, message_id)

            elif category == "SUSPICIOUS":
                move_to_suspicious(user_id, message_id)

            # SAFE → do nothing

        return {"status": "processed"}

    except Exception as e:
        logger.error(f"❌ Webhook error: {str(e)}")
        return Response(status_code=500)
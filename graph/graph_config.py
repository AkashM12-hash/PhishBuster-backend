import os

# Toggle Graph functionality
GRAPH_ENABLED = True

TENANT_ID = os.getenv("TENANT_ID", "")
CLIENT_ID = os.getenv("CLIENT_ID", "")
CLIENT_SECRET = os.getenv("CLIENT_SECRET", "")
WEBHOOK_URL = os.getenv("WEBHOOK_URL", "")

GRAPH_BASE_URL = "https://graph.microsoft.com/v1.0"
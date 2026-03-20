#graph_client.py
import requests
from graph.graph_config import TENANT_ID, CLIENT_ID, CLIENT_SECRET

def get_graph_token():
    url = f"https://login.microsoftonline.com/{TENANT_ID}/oauth2/v2.0/token"

    data = {
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "scope": "https://graph.microsoft.com/.default",
        "grant_type": "client_credentials"
    }

    response = requests.post(url, data=data)

    if response.status_code != 200:
        raise Exception("Graph authentication failed")

    return response.json()["access_token"]
def move_email_to_quarantine(user_email, message_id, folder="JunkEmail"):
    token = get_graph_token()

    url = f"https://graph.microsoft.com/v1.0/users/{user_email}/messages/{message_id}/move"

    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }

    data = {
        "destinationId": folder
    }

    response = requests.post(url, headers=headers, json=data)

    print("Graph move response:", response.status_code, response.text)

    return response.status_code in [200, 201]
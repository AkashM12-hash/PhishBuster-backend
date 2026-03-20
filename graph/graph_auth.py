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
        raise Exception(f"Graph authentication failed: {response.text}")

    return response.json()["access_token"]
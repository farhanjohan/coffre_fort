import json
import os

# Path to the JSON file storing user credentials
CREDENTIALS_FILE = "credentials.json"

def load_user_credentials():
    """Load user credentials from the JSON file."""
    if not os.path.exists(CREDENTIALS_FILE):
        return {}
    with open(CREDENTIALS_FILE, "r") as f:
        return json.load(f)

def save_user_credentials(user_credentials):
    """Save user credentials to the JSON file."""
    with open(CREDENTIALS_FILE, "w") as f:
        json.dump(user_credentials, f, indent=4)

"""Static review fixture only: never imported or executed by the demo."""
import requests


def fetch_status():
    response = requests.get(
        "https://status.example.invalid/health",
        verify=True,
        timeout=5,
    )
    response.raise_for_status()
    return response.text

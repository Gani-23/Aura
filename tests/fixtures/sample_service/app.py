import requests


def charge_customer(amount: int) -> dict:
    """Charge the payment provider and return a simple result."""
    response = requests.post("https://api.stripe.com/v1/charges", json={"amount": amount})
    return {"status": "submitted", "provider_status": response.status_code}


def notify_customer(email: str) -> None:
    """Notify the customer through the approved email provider."""
    requests.post("https://api.mailgun.net/v3/messages", json={"email": email})

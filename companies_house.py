"""
Companies House API client.
Free API — get your key at: https://developer.company-information.service.gov.uk/
Set it as environment variable: set CH_API_KEY=your-key-here
"""

import os
import requests

CH_API_KEY = os.environ.get("CH_API_KEY", "")
BASE_URL = "https://api.company-information.service.gov.uk"

def _get(path):
    if not CH_API_KEY:
        return {"error": "CH_API_KEY not set"}
    r = requests.get(BASE_URL + path, auth=(CH_API_KEY, ""), timeout=10)
    if r.status_code == 200:
        return r.json()
    return {"error": f"HTTP {r.status_code}", "path": path}


def search_company(query):
    return _get(f"/search/companies?q={requests.utils.quote(query)}&items_per_page=10")


def get_company(number):
    return _get(f"/company/{number}")


def get_officers(number):
    return _get(f"/company/{number}/officers?items_per_page=50")


def get_appointments(officer_id):
    return _get(f"/officers/{officer_id}/appointments?items_per_page=50")


def search_officer(query):
    return _get(f"/search/officers?q={requests.utils.quote(query)}&items_per_page=20")


def search_disqualified(query):
    return _get(f"/search/disqualified-officers?q={requests.utils.quote(query)}&items_per_page=10")


def get_disqualified(officer_id):
    return _get(f"/disqualified-officers/natural/{officer_id}")


def get_company_filing_history(number):
    return _get(f"/company/{number}/filing-history?items_per_page=10")


def get_company_charges(number):
    return _get(f"/company/{number}/charges?items_per_page=10")

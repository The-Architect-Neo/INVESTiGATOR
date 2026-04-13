"""
Investigator Web Server
Run: python server.py
Then open: http://localhost:5000
"""

import os
import json
from datetime import datetime
from flask import Flask, request, jsonify, send_from_directory
from companies_house import (
    search_company, get_company, get_officers, get_appointments,
    search_officer, search_disqualified, get_disqualified,
    get_company_filing_history, get_company_charges
)

app = Flask(__name__, static_folder=".")

# ── KNOWN FORMATION AGENT / VIRTUAL OFFICE ADDRESSES ────────────
# Registered addresses associated with company formation agents and
# virtual office providers. A match is a soft red flag, not proof of wrongdoing.
KNOWN_FORMATION_ADDRESSES = [
    "blythswood square",
    "james watt street",
    "27 old gloucester street",
    "124 city road",
    "20-22 wenlock road",
    "71-75 shelton street",
    "kemp house",
    "84 eccleston square",
    "1 northumberland avenue",
    "86 james watt",
    "second home",
    "x-formation",
]


def check_formation_agent_address(address):
    addr_lower = address.lower() if address else ""
    return any(known in addr_lower for known in KNOWN_FORMATION_ADDRESSES)


# ── HELPERS ─────────────────────────────────────────────────────

def deduplicate_appointments(appointments):
    """
    Companies House sometimes returns multiple records for the same company
    (e.g. resigned and reappointed). Keep the most recent record per company number.
    """
    seen = {}
    for a in appointments:
        co_num = a.get("appointed_to", {}).get("company_number", "")
        if not co_num:
            continue
        if co_num not in seen:
            seen[co_num] = a
        else:
            # Keep the one with no resignation date (still active), or the later appointment
            existing_resigned = seen[co_num].get("resigned_on", "")
            this_resigned = a.get("resigned_on", "")
            if existing_resigned and not this_resigned:
                seen[co_num] = a
    return list(seen.values())


def red_flags(appointments, address=""):
    # Deduplicate before analysis so duplicate CH records don't trigger false flags
    appointments = deduplicate_appointments(appointments)

    flags = []
    dissolved = [a for a in appointments if
                 a.get("appointed_to", {}).get("company_status") in ["dissolved", "liquidation"]]
    resigned = [a for a in appointments if a.get("resigned_on")]
    active = [a for a in appointments if not a.get("resigned_on")]

    # Overall dissolved associations
    if len(dissolved) >= 2:
        flags.append(f"{len(dissolved)} dissolved company associations")

    # Director at dissolution — still listed as director when the company folded
    at_dissolution = [a for a in dissolved if not a.get("resigned_on")]
    if at_dissolution:
        names = ", ".join(a.get("appointed_to", {}).get("company_name", "Unknown") for a in at_dissolution)
        if len(at_dissolution) == 1:
            flags.append(f"Director at dissolution — never formally resigned from {names}")
        else:
            flags.append(f"Director at dissolution on {len(at_dissolution)} companies — never formally resigned ({names})")

    if len(resigned) >= 3:
        flags.append(f"Resigned from {len(resigned)} companies")

    # Active companies — named inline so you don't have to scroll to the table
    if len(active) >= 3:
        active_names = ", ".join(a.get("appointed_to", {}).get("company_name", "Unknown") for a in active)
        flags.append(f"Currently active in {len(active)} companies simultaneously — {active_names}")

    # Phoenix window — new appointment within 12 months of leaving a dissolved company
    dissolved_with_resignation = [a for a in dissolved if a.get("resigned_on")]
    appt_index = []
    for a in appointments:
        d = a.get("appointed_on", "")
        co_num = a.get("appointed_to", {}).get("company_number", "")
        co_name = a.get("appointed_to", {}).get("company_name", "")
        if d:
            try:
                appt_index.append((datetime.strptime(d, "%Y-%m-%d"), co_num, co_name))
            except:
                pass

    phoenix_flagged = False
    for a in dissolved_with_resignation:
        if phoenix_flagged:
            break
        resigned_str = a.get("resigned_on", "")
        dissolved_co_num = a.get("appointed_to", {}).get("company_number", "")
        dissolved_co_name = a.get("appointed_to", {}).get("company_name", "Unknown")
        try:
            resigned_date = datetime.strptime(resigned_str, "%Y-%m-%d")
        except:
            continue
        for appt_date, co_num, co_name in appt_index:
            if co_num == dissolved_co_num:
                continue
            delta = (appt_date - resigned_date).days
            if 0 < delta <= 365:
                flags.append(f"Possible phoenix — joined {co_name} within {delta} days of leaving dissolved {dissolved_co_name}")
                phoenix_flagged = True
                break

    # Formation agent / virtual office address
    if address and check_formation_agent_address(address):
        flags.append("Registered at known virtual office / formation agent address")

    # Rapid incorporation — two appointments within 180 days of each other
    dates = []
    for a in appointments:
        d = a.get("appointed_on", "")
        if d:
            try:
                dates.append(datetime.strptime(d, "%Y-%m-%d"))
            except:
                pass
    dates.sort()
    for i in range(len(dates) - 1):
        delta = (dates[i+1] - dates[i]).days
        if delta == 0:
            continue  # Same day is likely a data artifact, skip
        if delta < 180:
            flags.append(f"Two companies incorporated within {delta} days of each other")
            break

    return flags


def check_disqualification(name):
    results = search_disqualified(name)
    items = results.get("items", [])
    for item in items:
        if item.get("title", "").upper() == name.upper():
            return True, item
    return False, None


def build_officer_data(officer):
    o_name = officer.get("name", "Unknown")
    o_role = officer.get("officer_role", "")
    o_appointed = officer.get("appointed_on", "")
    o_resigned = officer.get("resigned_on", "")
    o_dob = officer.get("date_of_birth", {})
    o_dob_str = f"{o_dob.get('month', '')}/{o_dob.get('year', '')}" if o_dob else ""
    o_links = officer.get("links", {})
    o_id = o_links.get("officer", {}).get("appointments", "").split("/officers/")[-1].split("/")[0]

    appointments = []
    if o_id:
        appt_data = get_appointments(o_id)
        appointments = appt_data.get("items", [])

    o_address = officer.get("address", {})
    o_addr_str = ", ".join(filter(None, [
        o_address.get("premises"), o_address.get("address_line_1"),
        o_address.get("locality"), o_address.get("postal_code")
    ]))

    appointments = deduplicate_appointments(appointments)
    flags = red_flags(appointments, address=o_addr_str)

    # Disqualification check
    disqualified, disq_data = check_disqualification(o_name)
    if disqualified:
        flags.insert(0, "DISQUALIFIED DIRECTOR — appears on Insolvency Service register")

    appt_list = []
    for a in appointments:
        co = a.get("appointed_to", {})
        appt_list.append({
            "company_name": co.get("company_name", "Unknown"),
            "company_number": co.get("company_number", ""),
            "company_status": co.get("company_status", "unknown"),
            "appointed_on": a.get("appointed_on", ""),
            "resigned_on": a.get("resigned_on", "")
        })

    return {
        "name": o_name,
        "role": o_role,
        "appointed": o_appointed,
        "resigned": o_resigned,
        "dob": o_dob_str,
        "flags": flags,
        "appointments": appt_list
    }


# ── ROUTES ───────────────────────────────────────────────────────

@app.route("/")
def index():
    return send_from_directory(".", "index.html")


@app.route("/api/company", methods=["GET"])
def api_company():
    query = request.args.get("q", "").strip()
    if not query:
        return jsonify({"error": "No query provided"}), 400

    if query.replace(" ", "").isalnum() and len(query) <= 8:
        company = get_company(query.upper())
        if "error" in company:
            results = search_company(query)
            items = results.get("items", [])
            if not items:
                return jsonify({"error": "Company not found"}), 404
            company = get_company(items[0].get("company_number", ""))
    else:
        results = search_company(query)
        items = results.get("items", [])
        if not items:
            return jsonify({"error": "Company not found"}), 404
        company = get_company(items[0].get("company_number", ""))

    number = company.get("company_number", "")
    name = company.get("company_name", "Unknown")
    status = company.get("company_status", "unknown")
    created = company.get("date_of_creation", "Unknown")
    sic = company.get("sic_codes", [])
    address = company.get("registered_office_address", {})
    addr_str = ", ".join(filter(None, [
        address.get("address_line_1"), address.get("locality"), address.get("postal_code")
    ]))

    officers_data = get_officers(number)
    officers = officers_data.get("items", [])
    officer_profiles = [build_officer_data(o) for o in officers]

    # Company-level flags
    company_flags = []
    accounts = company.get("accounts", {})
    confirmation = company.get("confirmation_statement", {})
    if accounts.get("overdue"):
        company_flags.append("Accounts overdue — filing obligations not met")
    if confirmation.get("overdue"):
        company_flags.append("Confirmation statement overdue — may be approaching strike-off")
    if status in ["dissolved", "liquidation"]:
        company_flags.append(f"Company status: {status.upper()}")

    # Previous company names
    prev_names = company.get("previous_company_names", [])
    prev_names_list = [{"name": n.get("name", ""), "ceased": n.get("ceased_on", "")} for n in prev_names]
    if prev_names_list:
        company_flags.append(f"Company has traded under {len(prev_names_list)} previous name(s)")

    # Charges (secured debts)
    charges_data = get_company_charges(number)
    charges = charges_data.get("items", [])
    outstanding_charges = [c for c in charges if c.get("status") == "outstanding"]
    if outstanding_charges:
        company_flags.append(f"{len(outstanding_charges)} outstanding charge(s) registered against company")

    return jsonify({
        "company": {
            "name": name,
            "number": number,
            "status": status,
            "created": created,
            "sic": sic,
            "address": addr_str,
            "flags": company_flags,
            "previous_names": prev_names_list
        },
        "officers": officer_profiles
    })


def name_matches(result_name, query):
    """Check if the result name closely matches the search query."""
    result_parts = set(result_name.upper().replace(",", "").split())
    query_parts = set(query.upper().split())
    # Every word in the query must appear in the result name
    return query_parts.issubset(result_parts)


@app.route("/api/person", methods=["GET"])
def api_person():
    query = request.args.get("q", "").strip()
    if not query:
        return jsonify({"error": "No query provided"}), 400

    results = search_officer(query)
    officers = results.get("items", [])
    if not officers:
        return jsonify({"error": "No officers found"}), 404

    # Filter to only results where the name actually contains all query words
    officers = [o for o in officers if name_matches(o.get("title", ""), query)]
    if not officers:
        return jsonify({"error": f"No officers found matching '{query}' — try adding a surname or middle name"}), 404

    profiles = []
    for officer in officers[:5]:
        o_name = officer.get("title", "Unknown")
        o_dob = officer.get("date_of_birth", {})
        o_dob_str = f"{o_dob.get('month', '')}/{o_dob.get('year', '')}" if o_dob else ""
        o_address = officer.get("address", {})
        addr_str = ", ".join(filter(None, [
            o_address.get("premises"), o_address.get("address_line_1"),
            o_address.get("locality"), o_address.get("postal_code")
        ]))
        o_id = officer.get("links", {}).get("self", "").split("/officers/")[-1].split("/")[0]

        appointments = []
        if o_id:
            appt_data = get_appointments(o_id)
            appointments = appt_data.get("items", [])

        flags = red_flags(appointments, address=addr_str)
        appt_list = []
        for a in appointments:
            co = a.get("appointed_to", {})
            appt_list.append({
                "company_name": co.get("company_name", "Unknown"),
                "company_number": co.get("company_number", ""),
                "company_status": co.get("company_status", "unknown"),
                "appointed_on": a.get("appointed_on", ""),
                "resigned_on": a.get("resigned_on", "")
            })

        profiles.append({
            "name": o_name,
            "dob": o_dob_str,
            "address": addr_str,
            "flags": flags,
            "appointments": appt_list
        })

    return jsonify({"results": profiles})


if __name__ == "__main__":
    if not os.environ.get("CH_API_KEY"):
        print("\nERROR: CH_API_KEY not set.")
    else:
        port = int(os.environ.get("PORT", 5000))
        print(f"\nInvestigator running on port {port}")
        app.run(debug=False, host="0.0.0.0", port=port)

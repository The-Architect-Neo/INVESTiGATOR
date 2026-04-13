"""
Investigator — Director Trail and Company Intelligence Tool
Usage:
  python investigator.py company <number or name>
  python investigator.py person <full name>
  python investigator.py network <company_number> <company_number> ...

Output: HTML report saved to /reports/
"""

import sys
import os
import json
from datetime import datetime
from companies_house import (
    search_company, get_company, get_officers,
    get_appointments, search_officer
)

REPORT_DIR = os.path.join(os.path.dirname(__file__), "reports")
os.makedirs(REPORT_DIR, exist_ok=True)


# ── RED FLAG DETECTION ──────────────────────────────────────────

def red_flags(appointments):
    flags = []
    dissolved = [a for a in appointments if a.get("resigned_on") or a.get("status") == "dissolved"]
    active = [a for a in appointments if not a.get("resigned_on")]

    if len(dissolved) >= 2:
        flags.append(f"{len(dissolved)} dissolved/resigned company associations found")
    if len(active) >= 3:
        flags.append(f"Currently active in {len(active)} companies simultaneously")

    # Check for companies set up within 6 months of each other
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
        if delta < 180:
            flags.append(f"Two companies incorporated within {delta} days of each other")
            break

    return flags


# ── HTML REPORT BUILDER ─────────────────────────────────────────

def build_html(title, sections):
    rows = ""
    for section in sections:
        rows += f"""
        <div class="section">
            <h2>{section['title']}</h2>
            {section['content']}
        </div>"""

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>{title}</title>
<style>
  body {{ font-family: Arial, sans-serif; max-width: 960px; margin: 40px auto; padding: 0 20px; color: #222; }}
  h1 {{ border-bottom: 3px solid #c00; padding-bottom: 10px; }}
  h2 {{ color: #c00; margin-top: 30px; }}
  .section {{ margin-bottom: 30px; }}
  table {{ width: 100%; border-collapse: collapse; margin-top: 10px; }}
  th {{ background: #222; color: #fff; padding: 8px; text-align: left; }}
  td {{ padding: 8px; border-bottom: 1px solid #ddd; }}
  tr:hover {{ background: #f9f9f9; }}
  .flag {{ background: #fff3cd; border-left: 4px solid #c00; padding: 8px 12px; margin: 6px 0; }}
  .dissolved {{ color: #c00; font-weight: bold; }}
  .active {{ color: #2a7a2a; font-weight: bold; }}
  .meta {{ color: #666; font-size: 0.9em; margin-top: 5px; }}
</style>
</head>
<body>
<h1>{title}</h1>
<p class="meta">Generated: {datetime.now().strftime("%d %B %Y %H:%M")} | Source: Companies House public API</p>
{rows}
</body>
</html>"""


# ── COMPANY INVESTIGATION ───────────────────────────────────────

def investigate_company(query):
    print(f"\nSearching: {query}")

    # If it looks like a company number, go direct
    if query.replace(" ", "").isalnum() and len(query) <= 8:
        company = get_company(query.upper())
        if "error" not in company:
            companies = [company]
        else:
            results = search_company(query)
            companies = results.get("items", [])[:1]
    else:
        results = search_company(query)
        companies = results.get("items", [])[:1]

    if not companies:
        print("No company found.")
        return

    c = companies[0]
    number = c.get("company_number", "")
    name = c.get("company_name", c.get("title", "Unknown"))
    status = c.get("company_status", "unknown")
    date_created = c.get("date_of_creation", c.get("incorporated_on", "Unknown"))
    sic = c.get("sic_codes", [])
    address = c.get("registered_office_address", {})
    addr_str = ", ".join(filter(None, [
        address.get("address_line_1"), address.get("locality"),
        address.get("postal_code")
    ]))

    print(f"Found: {name} ({number})")

    # Get officers
    officers_data = get_officers(number)
    officers = officers_data.get("items", [])

    # For each officer, get their full appointment history
    all_appointments = []
    officer_profiles = []

    for officer in officers:
        o_name = officer.get("name", "Unknown")
        o_role = officer.get("officer_role", "")
        o_appointed = officer.get("appointed_on", "")
        o_resigned = officer.get("resigned_on", "")
        o_dob = officer.get("date_of_birth", {})
        o_dob_str = f"{o_dob.get('month', '')}/{o_dob.get('year', '')}" if o_dob else ""
        o_links = officer.get("links", {})
        o_id = o_links.get("officer", {}).get("appointments", "").split("/officers/")[-1].split("/")[0]

        print(f"  Pulling history for: {o_name}")
        appointments = []
        if o_id:
            appt_data = get_appointments(o_id)
            appointments = appt_data.get("items", [])
            all_appointments.extend(appointments)

        flags = red_flags(appointments)
        officer_profiles.append({
            "name": o_name,
            "role": o_role,
            "appointed": o_appointed,
            "resigned": o_resigned,
            "dob": o_dob_str,
            "appointments": appointments,
            "flags": flags,
            "id": o_id
        })

    # Build report sections
    sections = []

    # Company overview
    status_class = "active" if status == "active" else "dissolved"
    overview_html = f"""
    <table>
      <tr><th>Field</th><th>Detail</th></tr>
      <tr><td>Company Number</td><td>{number}</td></tr>
      <tr><td>Status</td><td class="{status_class}">{status.upper()}</td></tr>
      <tr><td>Incorporated</td><td>{date_created}</td></tr>
      <tr><td>Registered Address</td><td>{addr_str}</td></tr>
      <tr><td>SIC Codes</td><td>{", ".join(sic) if sic else "Not shown"}</td></tr>
    </table>"""
    sections.append({"title": f"Company Overview — {name}", "content": overview_html})

    # Officers and their histories
    for op in officer_profiles:
        rows_html = ""
        for a in op["appointments"]:
            co_name = a.get("appointed_to", {}).get("company_name", "Unknown")
            co_num = a.get("appointed_to", {}).get("company_number", "")
            co_status = a.get("appointed_to", {}).get("company_status", "unknown")
            appt_date = a.get("appointed_on", "")
            resigned_date = a.get("resigned_on", "")
            s_class = "dissolved" if co_status in ["dissolved", "liquidation"] else "active"
            rows_html += f"""<tr>
              <td><a href="https://find-and-update.company-information.service.gov.uk/company/{co_num}" target="_blank">{co_name}</a></td>
              <td>{co_num}</td>
              <td class="{s_class}">{co_status.upper()}</td>
              <td>{appt_date}</td>
              <td>{resigned_date or "Current"}</td>
            </tr>"""

        flags_html = "".join([f'<div class="flag">⚠ {f}</div>' for f in op["flags"]]) or "<p>No red flags detected.</p>"

        officer_html = f"""
        <p><strong>Role:</strong> {op['role']} | <strong>Appointed:</strong> {op['appointed']} | <strong>DOB:</strong> {op['dob']}</p>
        <h3>Red Flags</h3>
        {flags_html}
        <h3>Full Appointment History ({len(op['appointments'])} records)</h3>
        <table>
          <tr><th>Company</th><th>Number</th><th>Status</th><th>Appointed</th><th>Resigned</th></tr>
          {rows_html}
        </table>"""
        sections.append({"title": f"Director — {op['name']}", "content": officer_html})

    html = build_html(f"Company Investigation: {name}", sections)
    filename = f"{name.replace(' ', '_').lower()[:40]}_{number}.html"
    filepath = os.path.join(REPORT_DIR, filename)
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(html)

    print(f"\nReport saved: {filepath}")
    return filepath


# ── PERSON INVESTIGATION ────────────────────────────────────────

def investigate_person(name):
    print(f"\nSearching for: {name}")
    results = search_officer(name)
    officers = results.get("items", [])

    if not officers:
        print("No officer found.")
        return

    sections = []

    for officer in officers[:5]:
        o_name = officer.get("title", "Unknown")
        o_dob = officer.get("date_of_birth", {})
        o_dob_str = f"{o_dob.get('month', '')}/{o_dob.get('year', '')}" if o_dob else ""
        o_address = officer.get("address", {})
        addr_str = ", ".join(filter(None, [
            o_address.get("premises"), o_address.get("address_line_1"),
            o_address.get("locality"), o_address.get("postal_code")
        ]))
        o_links = officer.get("links", {})
        o_id = o_links.get("self", "").split("/officers/")[-1].split("/")[0]

        print(f"  Found: {o_name} (DOB {o_dob_str}) — pulling history")
        appointments = []
        if o_id:
            appt_data = get_appointments(o_id)
            appointments = appt_data.get("items", [])

        flags = red_flags(appointments)
        flags_html = "".join([f'<div class="flag">⚠ {f}</div>' for f in flags]) or "<p>No red flags detected.</p>"

        rows_html = ""
        for a in appointments:
            co_name = a.get("appointed_to", {}).get("company_name", "Unknown")
            co_num = a.get("appointed_to", {}).get("company_number", "")
            co_status = a.get("appointed_to", {}).get("company_status", "unknown")
            appt_date = a.get("appointed_on", "")
            resigned_date = a.get("resigned_on", "")
            s_class = "dissolved" if co_status in ["dissolved", "liquidation"] else "active"
            rows_html += f"""<tr>
              <td><a href="https://find-and-update.company-information.service.gov.uk/company/{co_num}" target="_blank">{co_name}</a></td>
              <td>{co_num}</td>
              <td class="{s_class}">{co_status.upper()}</td>
              <td>{appt_date}</td>
              <td>{resigned_date or "Current"}</td>
            </tr>"""

        person_html = f"""
        <p><strong>DOB:</strong> {o_dob_str} | <strong>Address:</strong> {addr_str}</p>
        <h3>Red Flags</h3>
        {flags_html}
        <h3>Full Appointment History ({len(appointments)} records)</h3>
        <table>
          <tr><th>Company</th><th>Number</th><th>Status</th><th>Appointed</th><th>Resigned</th></tr>
          {rows_html}
        </table>"""
        sections.append({"title": f"Officer — {o_name}", "content": person_html})

    html = build_html(f"Person Investigation: {name}", sections)
    filename = f"person_{name.replace(' ', '_').lower()[:40]}.html"
    filepath = os.path.join(REPORT_DIR, filename)
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(html)

    print(f"\nReport saved: {filepath}")
    return filepath


# ── MAIN ────────────────────────────────────────────────────────

def main():
    if len(sys.argv) < 3:
        print("Usage:")
        print("  python investigator.py company <number or name>")
        print("  python investigator.py person <full name>")
        sys.exit(1)

    mode = sys.argv[1].lower()
    query = " ".join(sys.argv[2:])

    if not os.environ.get("CH_API_KEY"):
        print("\nERROR: Set your Companies House API key first.")
        print("  Get a free key at: https://developer.company-information.service.gov.uk/")
        print("  Then run: set CH_API_KEY=your-key-here")
        sys.exit(1)

    if mode == "company":
        investigate_company(query)
    elif mode == "person":
        investigate_person(query)
    else:
        print(f"Unknown mode: {mode}. Use 'company' or 'person'.")


if __name__ == "__main__":
    main()

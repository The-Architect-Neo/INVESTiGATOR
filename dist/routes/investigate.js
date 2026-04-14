"use strict";
/**
 * INVESTiGATOR — Intelligence Route
 * ─────────────────────────────────────────────────────────────────
 * Public intelligence aggregator for fraud investigation.
 * Fans out to multiple free public databases concurrently and
 * returns structured results with risk flags.
 *
 * SUPPORTED LOOKUP TYPES
 * ──────────────────────
 *   company  → Companies House (company profile, directors, charges, insolvency)
 *              + FCA Register (is the firm regulated?)
 *   fca      → FCA Register (regulated firms and individuals)
 *   domain   → RDAP/WHOIS (registration, registrar, nameservers)
 *              + VirusTotal (malware / phishing reputation)
 *   ip       → IPinfo (geolocation, ISP, ASN)
 *              + RIPE RDAP (netblock ownership)
 *   postcode → Postcodes.io — UK postcode enrichment (free, no key)
 *   phone    → UK format validation + carrier analysis
 *   email    → Format, disposable check, MX, HIBP breach lookup
 *
 * NOTE ON BT PHONE BOOK
 * ─────────────────────
 * BT does NOT provide a public phone directory API.
 * 118500.co.uk (formerly BT-owned) has no programmatic access.
 * 192.com, Truecaller, etc. are all paywalled/closed.
 * Phone lookups here return format analysis + Ofcom carrier data only.
 * For live subscriber lookup, contact BT Business directly.
 *
 * ENV VARIABLES (all optional — graceful degradation if missing)
 * ──────────────────────────────────────────────────────────────
 *   COMPANIES_HOUSE_API_KEY   Free: developer.company-information.service.gov.uk
 *   VIRUSTOTAL_API_KEY        Free: virustotal.com/gui/join-us
 *   IPINFO_TOKEN              Free tier works without (50k req/mo limit applies)
 *   NUMVERIFY_API_KEY         Free: numverify.com (100 req/mo on free tier)
 *   ABUSEIPDB_API_KEY         Free: abuseipdb.com (1,000 checks/day)
 *   URLSCAN_API_KEY           Free: urlscan.io (5,000 scans/day)
 *   PHISHTANK_API_KEY         Free: phishtank.org (increases rate limits)
 *   CHARITY_COMMISSION_KEY    Free: register-of-charities.charitycommission.gov.uk/register/api
 *   HIBP_API_KEY              Paid £3.50/mo: haveibeenpwned.com/API/Key
 *   CANARY_WEBHOOK_URL        Discord/Slack/webhook for breach alerts
 *
 * FAIR USE
 * ────────
 * Rate limit: 30 lookups per 15 minutes per IP.
 * This tool is free to use for legitimate fraud investigation.
 * Collaboration and integration proposals welcome.
 * Contact: axion-project@proton.me
 *
 * CANARIES
 * ────────
 * Input canaries are embedded below. If a canary value arrives as
 * a query, it means data containing that value leaked from our system.
 * See INVESTIGATOR_INPUT_CANARIES for full list.
 *
 * ─────────────────────────────────────────────────────────────────
 * CANARY INDEX — keep these private, never share externally
 * ─────────────────────────────────────────────────────────────────
 *   CANARY-INV-CO-001     Fictitious company query sentinel
 *   CANARY-INV-PHONE-001  Ofcom reserved test number (never real subscriber)
 *   CANARY-INV-DOMAIN-001 Canary domain — not a real registrar record
 *   CANARY-INV-IP-001     RFC 5737 TEST-NET address — never routable
 *   CANARY-INV-POST-001   Fictitious UK postcode — Postcodes.io will 404
 *   CANARY-INV-EMAIL-001  Canary email address
 * ─────────────────────────────────────────────────────────────────
 */
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = require("express");
const express_rate_limit_1 = __importDefault(require("express-rate-limit"));
const zod_1 = require("zod");
const terms_1 = require("../legal/terms");
const canary_1 = require("../utils/canary");
// ──────────────────────────────────────────────────────────────────
// Investigator canary values — INPUT sentinels
// If any of these arrive in a query, alert immediately.
// They are planted in outputs/reports so leakage is traceable.
// ──────────────────────────────────────────────────────────────────
const INVESTIGATOR_INPUT_CANARIES = {
    'sv-canary-co': 'CANARY-INV-CO-001', // fake company name
    'sc999998': 'CANARY-INV-CO-001', // fake Companies House number
    '+447700900001': 'CANARY-INV-PHONE-001', // Ofcom reserved test range
    '07700900001': 'CANARY-INV-PHONE-001',
    'sv-canary.co.uk': 'CANARY-INV-DOMAIN-001',
    'sv-canary-test.com': 'CANARY-INV-DOMAIN-001',
    '192.0.2.254': 'CANARY-INV-IP-001', // RFC 5737 TEST-NET — never routable
    'sv1 0cv': 'CANARY-INV-POST-001', // fictitious postcode
    'sv10cv': 'CANARY-INV-POST-001',
    'canary@sv-canary.co.uk': 'CANARY-INV-EMAIL-001', // canary email address
};
function checkInputCanary(query, type, req) {
    const normalised = query.toLowerCase().trim();
    const canaryRef = INVESTIGATOR_INPUT_CANARIES[normalised];
    if (canaryRef) {
        (0, canary_1.alertCanaryTripped)(canaryRef, {
            path: req.path,
            type,
            ip: req.ip,
            userAgent: req.get('user-agent'),
            note: 'Input canary queried — possible data leakage event',
        }).catch(() => { });
    }
}
// ──────────────────────────────────────────────────────────────────
// Rate limiter — stricter than global (each lookup fans out to
// multiple external APIs — 30/15min is reasonable fair use)
// ──────────────────────────────────────────────────────────────────
const investigateLimiter = (0, express_rate_limit_1.default)({
    windowMs: 15 * 60 * 1000,
    max: 30,
    standardHeaders: true,
    legacyHeaders: false,
    message: {
        error: 'Investigation rate limit reached.',
        note: 'Fair use: 30 lookups per 15 minutes. Contact axion-project@proton.me for higher limits.',
    },
});
// ──────────────────────────────────────────────────────────────────
// Input validation
// ──────────────────────────────────────────────────────────────────
const QUERY_TYPES = ['company', 'person', 'fca', 'domain', 'ip', 'postcode', 'phone', 'email'];
const InvestigateSchema = zod_1.z.object({
    type: zod_1.z.enum(QUERY_TYPES),
    query: zod_1.z.string().min(1).max(200).trim(),
});
// ──────────────────────────────────────────────────────────────────
// HTTP helper — fetch with timeout
// Node 18+ has native fetch. If you're on Node 16, install node-fetch.
// Return type is inferred from global fetch (Fetch API Response, not Express Response).
// ──────────────────────────────────────────────────────────────────
async function fetchWithTimeout(url, options = {}, timeoutMs = 8000) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
        return await fetch(url, { ...options, signal: controller.signal });
    }
    finally {
        clearTimeout(timer);
    }
}
// ══════════════════════════════════════════════════════════════════
// SOURCE MODULES — each is an independent async function.
// Returns { source, status, data } — never throws (returns error obj).
// status: 'ok' | 'error' | 'not_configured' | 'not_found'
// ══════════════════════════════════════════════════════════════════
// ──────────────────────────────────────────────────────────────────
// Companies House — free UK government company registry
// Register: developer.company-information.service.gov.uk
// Docs: developer-specs.company-information.service.gov.uk
// ──────────────────────────────────────────────────────────────────
async function lookupCompaniesHouse(query) {
    const key = process.env.COMPANIES_HOUSE_API_KEY;
    if (!key) {
        return {
            source: 'companies_house',
            status: 'not_configured',
            note: 'Set COMPANIES_HOUSE_API_KEY — free at developer.company-information.service.gov.uk',
        };
    }
    try {
        const auth = Buffer.from(key + ':').toString('base64');
        const url = `https://api.company-information.service.gov.uk/search/companies?q=${encodeURIComponent(query)}&items_per_page=5`;
        const res = await fetchWithTimeout(url, {
            headers: { Authorization: `Basic ${auth}` },
        });
        if (!res.ok) {
            return { source: 'companies_house', status: 'error', httpStatus: res.status };
        }
        const json = await res.json();
        // Risk flags — dissolved/liquidation companies are often fraud vectors
        const flags = [];
        for (const item of json.items ?? []) {
            if (['dissolved', 'liquidation', 'administration', 'receivership', 'voluntary-arrangement']
                .includes(item.company_status)) {
                flags.push(`DISSOLVED_OR_INSOLVENT: ${item.title} (${item.company_number}) — status: ${item.company_status}`);
            }
        }
        return {
            source: 'companies_house',
            status: 'ok',
            total_results: json.total_results ?? 0,
            results: (json.items ?? []).map(i => ({
                company_number: i.company_number,
                name: i.title,
                status: i.company_status,
                type: i.company_type,
                incorporated: i.date_of_creation,
                address: i.registered_office_address,
            })),
            flags,
        };
    }
    catch (err) {
        return { source: 'companies_house', status: 'error', error: String(err) };
    }
}
// ──────────────────────────────────────────────────────────────────
// Companies House — director/officer lookup by company number
// ──────────────────────────────────────────────────────────────────
async function lookupCompanyOfficers(companyNumber) {
    const key = process.env.COMPANIES_HOUSE_API_KEY;
    if (!key)
        return null;
    try {
        const auth = Buffer.from(key + ':').toString('base64');
        const url = `https://api.company-information.service.gov.uk/company/${encodeURIComponent(companyNumber)}/officers?items_per_page=10`;
        const res = await fetchWithTimeout(url, {
            headers: { Authorization: `Basic ${auth}` },
        });
        if (!res.ok)
            return null;
        const json = await res.json();
        return (json.items ?? []).map(o => ({
            name: o.name,
            role: o.officer_role,
            appointed: o.appointed_on,
            resigned: o.resigned_on ?? null,
            nationality: o.nationality,
        }));
    }
    catch {
        return null;
    }
}
// ──────────────────────────────────────────────────────────────────
// Companies House — person / officer search by name
// Searches the CH officer index, fetches appointments for each match,
// and surfaces red flags: dissolved associations, phoenix patterns,
// multiple simultaneous directorships, director at dissolution.
// ──────────────────────────────────────────────────────────────────
async function lookupPersonByName(query) {
    const key = process.env.COMPANIES_HOUSE_API_KEY;
    if (!key) {
        return {
            source: 'ch_person_search',
            status: 'not_configured',
            note: 'Set COMPANIES_HOUSE_API_KEY — free at developer.company-information.service.gov.uk',
        };
    }
    try {
        const auth = Buffer.from(key + ':').toString('base64');
        const url = `https://api.company-information.service.gov.uk/search/officers?q=${encodeURIComponent(query)}&items_per_page=10`;
        const res = await fetchWithTimeout(url, { headers: { Authorization: `Basic ${auth}` } });
        if (!res.ok) {
            return { source: 'ch_person_search', status: 'error', httpStatus: res.status };
        }
        const json = await res.json();
        const items = json.items ?? [];
        // Filter to results where every query word appears in the name
        const queryWords = query.toUpperCase().split(/\s+/).filter(Boolean);
        const matched = items.filter(o => {
            const name = (o.title || '').toUpperCase();
            return queryWords.every(w => name.includes(w));
        });
        const profiles = await Promise.all(matched.slice(0, 3).map(async (officer) => {
            const officerId = (officer.links?.self || '').split('/officers/')[1]?.split('/')[0];
            let appointments = [];
            if (officerId) {
                try {
                    const ar = await fetchWithTimeout(`https://api.company-information.service.gov.uk/officers/${officerId}/appointments?items_per_page=50`, { headers: { Authorization: `Basic ${auth}` } });
                    if (ar.ok) {
                        const aj = await ar.json();
                        appointments = aj.items ?? [];
                    }
                }
                catch { /* ignore single appointment fetch failure */ }
            }
            // Red flags — ported from the original fraud detection logic
            const flags = [];
            const dissolved = appointments.filter(a => ['dissolved', 'liquidation', 'administration', 'receivership'].includes(a.appointed_to?.company_status));
            const active = appointments.filter(a => !a.resigned_on);
            const resigned = appointments.filter(a => a.resigned_on);
            if (dissolved.length >= 2)
                flags.push(`${dissolved.length} dissolved or insolvent company associations`);
            const atDissolution = dissolved.filter(a => !a.resigned_on);
            if (atDissolution.length) {
                const names = atDissolution.map(a => a.appointed_to?.company_name || 'Unknown').join(', ');
                flags.push(`Director at dissolution — never formally resigned from ${names}`);
            }
            if (resigned.length >= 3)
                flags.push(`Resigned from ${resigned.length} companies`);
            if (active.length >= 3) {
                const names = active.slice(0, 3).map(a => a.appointed_to?.company_name || 'Unknown').join(', ');
                flags.push(`Currently active in ${active.length} companies simultaneously — ${names}${active.length > 3 ? '...' : ''}`);
            }
            const dob = officer.date_of_birth;
            return {
                name: officer.title || query,
                dob: dob ? `${dob.month}/${dob.year}` : null,
                total_appointments: appointments.length,
                appointments: appointments.map(a => ({
                    company_name: a.appointed_to?.company_name || 'Unknown',
                    company_number: a.appointed_to?.company_number || '',
                    company_status: a.appointed_to?.company_status || 'unknown',
                    role: a.officer_role || '',
                    appointed_on: a.appointed_on || '',
                    resigned_on: a.resigned_on || null,
                })),
                flags,
            };
        }));
        const allFlags = profiles.flatMap(p => p.flags);
        return {
            source: 'ch_person_search',
            status: profiles.length > 0 ? 'ok' : 'not_found',
            total_results: json.total_results ?? 0,
            note: profiles.length === 0 ? `No officer found matching "${query}" in Companies House` : undefined,
            profiles,
            flags: allFlags,
        };
    }
    catch (err) {
        return { source: 'ch_person_search', status: 'error', error: String(err) };
    }
}
// ──────────────────────────────────────────────────────────────────
// FCA Register — Financial Conduct Authority regulated firms
// No API key needed. Official UK regulator database.
// ──────────────────────────────────────────────────────────────────
async function lookupFCA(query) {
    try {
        const url = `https://register.fca.org.uk/services/V0.1/Firm?term=${encodeURIComponent(query)}`;
        const res = await fetchWithTimeout(url, {
            headers: { Accept: 'application/json' },
        });
        if (res.status === 404) {
            return { source: 'fca_register', status: 'not_found', note: 'No FCA-regulated firm found for this query' };
        }
        if (!res.ok) {
            return {
                source: 'fca_register',
                status: 'check_manually',
                note: 'FCA Register is not accessible from this server. Verify the firm directly using the link below.',
                manual_check: `https://register.fca.org.uk/s/?q=${encodeURIComponent(query)}`,
            };
        }
        const json = await res.json();
        const items = json.Data ?? [];
        const flags = [];
        if (items.length === 0) {
            flags.push('NOT_FCA_REGISTERED: No matching entry in FCA Register — verify if regulated activities claimed');
        }
        for (const firm of items) {
            if (firm['Current Authorisation Status'] &&
                !['Authorised', 'Registered'].includes(firm['Current Authorisation Status'])) {
                flags.push(`FCA_STATUS_CONCERN: ${firm.Name} — status: ${firm['Current Authorisation Status']}`);
            }
        }
        return {
            source: 'fca_register',
            status: 'ok',
            count: items.length,
            results: items.map(f => ({
                name: f.Name,
                reference: f['Reference Number'],
                auth_status: f['Current Authorisation Status'],
                firm_type: f['Firm Type'],
            })),
            flags,
        };
    }
    catch (err) {
        return { source: 'fca_register', status: 'error', error: String(err) };
    }
}
// ──────────────────────────────────────────────────────────────────
// FCA Warning List — known scam firms and clone firm alerts
// No key needed. Distinct from the FCA Register.
// Manual check: fca.org.uk/consumers/scamsmart
// ──────────────────────────────────────────────────────────────────
async function lookupFCAWarning(query) {
    try {
        const url = `https://register.fca.org.uk/services/V0.1/Warning?term=${encodeURIComponent(query)}`;
        const res = await fetchWithTimeout(url, {
            headers: { Accept: 'application/json' },
        });
        if (res.status === 404) {
            return { source: 'fca_warning_list', status: 'not_found', note: 'No FCA warning notices found for this query' };
        }
        if (!res.ok) {
            return {
                source: 'fca_warning_list',
                status: 'check_manually',
                note: 'FCA Warning List is not accessible from this server. Check for scam alerts directly using the link below.',
                manual_check: `https://www.fca.org.uk/consumers/scamsmart/warning-list-search?q=${encodeURIComponent(query)}`,
            };
        }
        const json = await res.json();
        const items = json.Data ?? [];
        const flags = [];
        if (items.length > 0) {
            flags.push(`FCA_WARNING_MATCH: ${items.length} FCA warning notice(s) found — this firm or name is flagged as unauthorised or fraudulent`);
        }
        return {
            source: 'fca_warning_list',
            status: 'ok',
            count: items.length,
            results: items.map(i => ({
                name: i.Name,
                url: i['URL of Firm'],
                date: i.Date,
                warning_type: i['Warning Type'],
            })),
            flags,
            manual_check: 'https://www.fca.org.uk/consumers/scamsmart',
        };
    }
    catch (err) {
        return {
            source: 'fca_warning_list',
            status: 'error',
            error: String(err),
            manual_check: 'https://www.fca.org.uk/consumers/scamsmart',
        };
    }
}
// ──────────────────────────────────────────────────────────────────
// Companies House — disqualified directors register
// Same API key as company search. Free.
// ──────────────────────────────────────────────────────────────────
async function lookupDisqualifiedDirectors(query) {
    const key = process.env.COMPANIES_HOUSE_API_KEY;
    if (!key) {
        return {
            source: 'ch_disqualified_directors',
            status: 'not_configured',
            note: 'Set COMPANIES_HOUSE_API_KEY — same key as company search',
        };
    }
    try {
        const auth = Buffer.from(key + ':').toString('base64');
        const url = `https://api.company-information.service.gov.uk/search/disqualified-officers?q=${encodeURIComponent(query)}&items_per_page=5`;
        const res = await fetchWithTimeout(url, {
            headers: { Authorization: `Basic ${auth}` },
        });
        if (!res.ok) {
            return { source: 'ch_disqualified_directors', status: 'error', httpStatus: res.status };
        }
        const json = await res.json();
        const items = json.items ?? [];
        const flags = [];
        for (const person of items) {
            const activeDisq = (person.disqualifications ?? []).filter(d => {
                if (!d.disqualified_until)
                    return true;
                return new Date(d.disqualified_until) > new Date();
            });
            if (activeDisq.length > 0) {
                flags.push(`ACTIVE_DISQUALIFICATION: ${person.title} has ${activeDisq.length} active director disqualification(s)`);
            }
        }
        return {
            source: 'ch_disqualified_directors',
            status: 'ok',
            total_results: json.total_results ?? 0,
            results: items.map(p => ({
                name: p.title,
                description: p.description,
                disqualifications: (p.disqualifications ?? []).map(d => ({
                    type: d.disqualification_type,
                    from: d.disqualified_from,
                    until: d.disqualified_until ?? 'ongoing',
                    reason: d.reason?.description_identifier,
                })),
            })),
            flags,
        };
    }
    catch (err) {
        return { source: 'ch_disqualified_directors', status: 'error', error: String(err) };
    }
}
// ──────────────────────────────────────────────────────────────────
// Companies House — charges (mortgages / security interests)
// Outstanding charges = financial distress flag.
// ──────────────────────────────────────────────────────────────────
async function lookupCompanyCharges(companyNumber) {
    const key = process.env.COMPANIES_HOUSE_API_KEY;
    if (!key)
        return null;
    try {
        const auth = Buffer.from(key + ':').toString('base64');
        const url = `https://api.company-information.service.gov.uk/company/${encodeURIComponent(companyNumber)}/charges?items_per_page=10`;
        const res = await fetchWithTimeout(url, {
            headers: { Authorization: `Basic ${auth}` },
        });
        if (res.status === 404)
            return null;
        if (!res.ok)
            return null;
        const json = await res.json();
        const outstanding = (json.items ?? []).filter(c => c.status === 'outstanding');
        const flags = [];
        if (outstanding.length > 0) {
            flags.push(`OUTSTANDING_CHARGES: ${outstanding.length} outstanding charge(s) registered against this company`);
        }
        return {
            source: 'ch_charges',
            status: 'ok',
            total: json.total_count ?? 0,
            outstanding: outstanding.length,
            satisfied: json.satisfied_count ?? 0,
            charges: (json.items ?? []).map(c => ({
                status: c.status,
                type: c.classification?.description,
                created: c.created_on,
                satisfied_on: c.satisfied_on ?? null,
                secured_to: (c.persons_entitled ?? []).map(p => p.name),
            })),
            flags,
        };
    }
    catch {
        return null;
    }
}
// ──────────────────────────────────────────────────────────────────
// Companies House — filing history
// Fraud signals: dormant company suddenly active, burst filings,
// financial accounts filed very soon after incorporation.
// ──────────────────────────────────────────────────────────────────
async function lookupFilingHistory(companyNumber) {
    const key = process.env.COMPANIES_HOUSE_API_KEY;
    if (!key)
        return null;
    try {
        const auth = Buffer.from(key + ':').toString('base64');
        const url = `https://api.company-information.service.gov.uk/company/${encodeURIComponent(companyNumber)}/filing-history?items_per_page=10&category=accounts`;
        const res = await fetchWithTimeout(url, {
            headers: { Authorization: `Basic ${auth}` },
        });
        if (res.status === 404)
            return null;
        if (!res.ok)
            return null;
        const json = await res.json();
        const items = json.items ?? [];
        const flags = [];
        if (json.filing_history_status === 'filing-history-available') {
            const dates = items
                .map(i => i.date ? new Date(i.date).getTime() : null)
                .filter(Boolean);
            if (dates.length >= 2) {
                const newest = Math.max(...dates);
                const oldest = Math.min(...dates);
                const gapDays = (newest - oldest) / 86400000;
                if (gapDays < 30 && items.length >= 3) {
                    flags.push(`FILING_BURST: ${items.length} filings in ${Math.round(gapDays)} days — unusual activity pattern`);
                }
            }
            const earliest = items.at(-1);
            if (earliest?.date) {
                const ageDays = (Date.now() - new Date(earliest.date).getTime()) / 86400000;
                if (ageDays < 90 && items.some(i => i.category === 'accounts')) {
                    flags.push(`EARLY_ACCOUNTS: Financial accounts filed within 90 days of company activity — verify legitimacy`);
                }
            }
        }
        return {
            source: 'ch_filing_history',
            status: 'ok',
            total_filings: json.total_count ?? 0,
            recent: items.map(i => ({
                type: i.type,
                description: i.description,
                date: i.date,
                category: i.category,
            })),
            flags,
        };
    }
    catch {
        return null;
    }
}
// ──────────────────────────────────────────────────────────────────
// Charity Commission — UK registered charities
// Catches fake charity scams. No key needed for basic search.
// ──────────────────────────────────────────────────────────────────
async function lookupCharityCommission(query) {
    try {
        const key = process.env.CHARITY_COMMISSION_KEY;
        const url = `https://api.charitycommission.gov.uk/register/api/searchCharities?q=${encodeURIComponent(query)}&pageNumber=1&pageSize=5`;
        const headers = { Accept: 'application/json' };
        if (key)
            headers['Ocp-Apim-Subscription-Key'] = key;
        const res = await fetchWithTimeout(url, { headers });
        if (res.status === 404 || res.status === 204) {
            return { source: 'charity_commission', status: 'not_found', note: 'No registered UK charity found' };
        }
        if (!res.ok) {
            return {
                source: 'charity_commission',
                status: 'error',
                httpStatus: res.status,
                manual_check: 'https://register-of-charities.charitycommission.gov.uk/charity-search',
            };
        }
        const json = await res.json();
        const charities = json.charities ?? [];
        const flags = [];
        if (charities.length === 0) {
            flags.push('NOT_REGISTERED_CHARITY: No matching entry in Charity Commission register');
        }
        for (const c of charities) {
            if (c.charityStatus === 'removed' || c.charitySubStatus === 'removed') {
                flags.push(`REMOVED_CHARITY: ${c.charityName} (${c.registeredCharityNumber}) has been removed from the register`);
            }
        }
        return {
            source: 'charity_commission',
            status: 'ok',
            total: json.totalResultCount ?? charities.length,
            results: charities.map(c => ({
                number: c.registeredCharityNumber,
                name: c.charityName,
                status: c.charityStatus,
                registered: c.dateOfRegistration,
                removed: c.dateOfRemoval ?? null,
                latest_income: c.latestIncome,
            })),
            flags,
        };
    }
    catch (err) {
        return {
            source: 'charity_commission',
            status: 'error',
            error: String(err),
            manual_check: 'https://register-of-charities.charitycommission.gov.uk/charity-search',
        };
    }
}
// ──────────────────────────────────────────────────────────────────
// RDAP / WHOIS — domain registration data (free, no key needed)
// Uses IANA RDAP bootstrap — routes to the correct TLD registry.
// ──────────────────────────────────────────────────────────────────
async function lookupRDAP(domain) {
    try {
        const clean = domain.replace(/^https?:\/\//i, '').split('/')[0].toLowerCase();
        const url = `https://rdap.org/domain/${encodeURIComponent(clean)}`;
        const res = await fetchWithTimeout(url);
        if (res.status === 404) {
            return { source: 'rdap_whois', status: 'not_found', domain: clean };
        }
        if (!res.ok) {
            return { source: 'rdap_whois', status: 'error', httpStatus: res.status };
        }
        const json = await res.json();
        const dates = {};
        for (const ev of json.events ?? []) {
            dates[ev.eventAction] = ev.eventDate;
        }
        const flags = [];
        const registered = dates['registration'];
        if (registered) {
            const ageDays = (Date.now() - new Date(registered).getTime()) / 86400000;
            if (ageDays < 30)
                flags.push(`RECENTLY_REGISTERED: Domain registered ${Math.round(ageDays)} days ago — common fraud indicator`);
        }
        return {
            source: 'rdap_whois',
            status: 'ok',
            domain: clean,
            rdap_status: json.status ?? [],
            dates,
            nameservers: (json.nameservers ?? []).map(n => n.ldhName),
            flags,
        };
    }
    catch (err) {
        return { source: 'rdap_whois', status: 'error', error: String(err) };
    }
}
// ──────────────────────────────────────────────────────────────────
// VirusTotal — domain/URL/IP reputation
// Free key: virustotal.com/gui/join-us (4 lookups/min, 500/day)
// ──────────────────────────────────────────────────────────────────
async function lookupVirusTotal(query, type) {
    const key = process.env.VIRUSTOTAL_API_KEY;
    if (!key) {
        return {
            source: 'virustotal',
            status: 'not_configured',
            note: 'Set VIRUSTOTAL_API_KEY — free at virustotal.com/gui/join-us',
        };
    }
    try {
        const endpoint = type === 'domain'
            ? `https://www.virustotal.com/api/v3/domains/${encodeURIComponent(query)}`
            : `https://www.virustotal.com/api/v3/ip_addresses/${encodeURIComponent(query)}`;
        const res = await fetchWithTimeout(endpoint, {
            headers: { 'x-apikey': key },
        });
        if (res.status === 404) {
            return { source: 'virustotal', status: 'not_found' };
        }
        if (!res.ok) {
            return { source: 'virustotal', status: 'error', httpStatus: res.status };
        }
        const json = await res.json();
        const stats = json.data?.attributes?.last_analysis_stats;
        const flags = [];
        if (stats) {
            if (stats.malicious > 0) {
                flags.push(`MALICIOUS_DETECTIONS: ${stats.malicious} security vendors flagged this as malicious`);
            }
            if (stats.suspicious > 0) {
                flags.push(`SUSPICIOUS_DETECTIONS: ${stats.suspicious} vendors flagged as suspicious`);
            }
        }
        const reputation = json.data?.attributes?.reputation ?? 0;
        if (reputation < -10) {
            flags.push(`LOW_REPUTATION: VirusTotal community reputation score ${reputation}`);
        }
        return {
            source: 'virustotal',
            status: 'ok',
            stats,
            reputation: json.data?.attributes?.reputation,
            categories: json.data?.attributes?.categories ?? {},
            last_analysed: json.data?.attributes?.last_analysis_date
                ? new Date((json.data.attributes.last_analysis_date) * 1000).toISOString()
                : null,
            flags,
        };
    }
    catch (err) {
        return { source: 'virustotal', status: 'error', error: String(err) };
    }
}
// ──────────────────────────────────────────────────────────────────
// PhishTank — community phishing URL database
// No key required. Key increases rate limits.
// Register: phishtank.org
// ──────────────────────────────────────────────────────────────────
async function lookupPhishTank(url) {
    try {
        const target = /^https?:\/\//i.test(url) ? url : `https://${url}`;
        const body = new URLSearchParams({ url: target, format: 'json' });
        const key = process.env.PHISHTANK_API_KEY;
        if (key)
            body.append('app_key', key);
        const res = await fetchWithTimeout('https://checkurl.phishtank.com/checkurl/', {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'User-Agent': 'INVESTiGATOR/1.0' },
            body: body.toString(),
        });
        if (!res.ok) {
            return { source: 'phishtank', status: 'error', httpStatus: res.status };
        }
        const json = await res.json();
        const r = json.results;
        const flags = [];
        if (r?.in_database && r?.verified) {
            flags.push(`PHISHTANK_CONFIRMED_PHISH: URL is a verified phishing page (ID: ${r.phish_id})`);
        }
        else if (r?.in_database && !r?.verified) {
            flags.push(`PHISHTANK_UNVERIFIED_REPORT: URL reported as phishing but not yet community-verified`);
        }
        return {
            source: 'phishtank',
            status: 'ok',
            in_database: r?.in_database ?? false,
            verified_phish: r?.verified ?? false,
            phish_id: r?.phish_id ?? null,
            verified_at: r?.verified_at ?? null,
            detail_page: r?.phish_detail_page ?? null,
            flags,
        };
    }
    catch (err) {
        return { source: 'phishtank', status: 'error', error: String(err) };
    }
}
// ──────────────────────────────────────────────────────────────────
// URLscan.io — URL analysis
// Search mode (no key): queries existing public scan results.
// Submit mode (key required): submits a new private scan.
// Register: urlscan.io (free — 5,000 scans/day)
// ──────────────────────────────────────────────────────────────────
async function lookupURLScan(domain) {
    try {
        const clean = domain.replace(/^https?:\/\//i, '').split('/')[0].toLowerCase();
        const key = process.env.URLSCAN_API_KEY;
        const searchUrl = `https://urlscan.io/api/v1/search/?q=domain:${encodeURIComponent(clean)}&size=3`;
        const searchRes = await fetchWithTimeout(searchUrl, {
            headers: { Accept: 'application/json' },
        });
        const flags = [];
        if (searchRes.ok) {
            const searchJson = await searchRes.json();
            const results = searchJson.results ?? [];
            for (const r of results) {
                if (r.verdicts?.overall?.malicious) {
                    flags.push(`URLSCAN_MALICIOUS: URLscan verdict is MALICIOUS for ${clean}`);
                }
                const score = r.verdicts?.overall?.score ?? 0;
                if (score > 50) {
                    flags.push(`URLSCAN_HIGH_SCORE: Threat score ${score} — above threshold`);
                }
                const categories = r.verdicts?.overall?.categories ?? [];
                if (categories.some(c => ['phishing', 'malware', 'cryptomining'].includes(c.toLowerCase()))) {
                    flags.push(`URLSCAN_CATEGORY: Categorised as ${categories.join(', ')}`);
                }
            }
            if (results.length > 0) {
                return {
                    source: 'urlscan',
                    status: 'ok',
                    domain: clean,
                    scan_count: searchJson.total ?? results.length,
                    latest_scan: results[0] ? {
                        time: results[0].task?.time,
                        url: results[0].task?.url,
                        country: results[0].page?.country,
                        server: results[0].page?.server,
                        verdict_malicious: results[0].verdicts?.overall?.malicious ?? false,
                        verdict_score: results[0].verdicts?.overall?.score ?? 0,
                        categories: results[0].verdicts?.overall?.categories ?? [],
                        screenshot: results[0].screenshot ?? null,
                        result_page: results[0]._id ? `https://urlscan.io/result/${results[0]._id}/` : null,
                    } : null,
                    flags,
                };
            }
        }
        if (!key) {
            return {
                source: 'urlscan',
                status: 'no_existing_scan',
                domain: clean,
                note: 'No existing scan found. Set URLSCAN_API_KEY (free at urlscan.io) to submit new scans.',
                flags: [],
            };
        }
        const submitRes = await fetchWithTimeout('https://urlscan.io/api/v1/scan/', {
            method: 'POST',
            headers: { 'API-Key': key, 'Content-Type': 'application/json' },
            body: JSON.stringify({ url: `https://${clean}`, visibility: 'private' }),
        });
        if (!submitRes.ok) {
            return { source: 'urlscan', status: 'error', httpStatus: submitRes.status };
        }
        const submitJson = await submitRes.json();
        return {
            source: 'urlscan',
            status: 'scan_submitted',
            domain: clean,
            scan_uuid: submitJson.uuid,
            result_url: submitJson.result,
            note: 'New private scan submitted. Results available in ~15 seconds at the result_url.',
            flags: [],
        };
    }
    catch (err) {
        return { source: 'urlscan', status: 'error', error: String(err) };
    }
}
// ──────────────────────────────────────────────────────────────────
// IPinfo — IP geolocation, ISP, ASN
// Free tier: 50k req/mo without token.
// Register: ipinfo.io (token extends limit)
// ──────────────────────────────────────────────────────────────────
async function lookupIPInfo(ip) {
    try {
        const token = process.env.IPINFO_TOKEN;
        const url = token
            ? `https://ipinfo.io/${encodeURIComponent(ip)}/json?token=${token}`
            : `https://ipinfo.io/${encodeURIComponent(ip)}/json`;
        const res = await fetchWithTimeout(url);
        if (!res.ok) {
            return { source: 'ipinfo', status: 'error', httpStatus: res.status };
        }
        const json = await res.json();
        const flags = [];
        if (json.bogon) {
            flags.push('BOGON_IP: Non-routable / private IP address range');
        }
        const highRiskOrgs = ['digitalocean', 'vultr', 'linode', 'hetzner', 'ovh', 'frantech', 'psychz'];
        const orgLower = (json.org ?? '').toLowerCase();
        if (highRiskOrgs.some(h => orgLower.includes(h))) {
            flags.push(`HOSTING_ASN: IP belongs to hosting/VPS provider (${json.org}) — common fraud infrastructure`);
        }
        return {
            source: 'ipinfo',
            status: 'ok',
            ip: json.ip,
            location: { city: json.city, region: json.region, country: json.country },
            org: json.org,
            hostname: json.hostname,
            timezone: json.timezone,
            bogon: json.bogon ?? false,
            flags,
        };
    }
    catch (err) {
        return { source: 'ipinfo', status: 'error', error: String(err) };
    }
}
// ──────────────────────────────────────────────────────────────────
// RIPE RDAP — IP netblock owner (European / global IP registry)
// Free, no auth. Best for European IP ranges.
// ──────────────────────────────────────────────────────────────────
async function lookupRIPE(ip) {
    try {
        const url = `https://rdap.db.ripe.net/ip/${encodeURIComponent(ip)}`;
        const res = await fetchWithTimeout(url);
        if (res.status === 404) {
            return { source: 'ripe_rdap', status: 'not_in_ripe', note: 'Not a RIPE-managed netblock — try ARIN/APNIC' };
        }
        if (!res.ok) {
            return { source: 'ripe_rdap', status: 'error', httpStatus: res.status };
        }
        const json = await res.json();
        return {
            source: 'ripe_rdap',
            status: 'ok',
            netblock_name: json.name,
            country: json.country,
            range: json.startAddress && json.endAddress
                ? `${json.startAddress} – ${json.endAddress}`
                : null,
            entities: (json.entities ?? []).map(e => ({ roles: e.roles, handle: e.handle })),
            flags: [],
        };
    }
    catch (err) {
        return { source: 'ripe_rdap', status: 'error', error: String(err) };
    }
}
// ──────────────────────────────────────────────────────────────────
// AbuseIPDB — community-reported IP abuse database
// Free tier: 1,000 checks/day. Key required (free registration).
// Register: abuseipdb.com
// ──────────────────────────────────────────────────────────────────
async function lookupAbuseIPDB(ip) {
    const key = process.env.ABUSEIPDB_API_KEY;
    if (!key) {
        return {
            source: 'abuseipdb',
            status: 'not_configured',
            note: 'Set ABUSEIPDB_API_KEY — free at abuseipdb.com (1,000 checks/day)',
        };
    }
    try {
        const url = `https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(ip)}&maxAgeInDays=90&verbose`;
        const res = await fetchWithTimeout(url, {
            headers: { Key: key, Accept: 'application/json' },
        });
        if (!res.ok) {
            return { source: 'abuseipdb', status: 'error', httpStatus: res.status };
        }
        const json = await res.json();
        const d = json.data;
        const flags = [];
        const score = d?.abuseConfidenceScore ?? 0;
        if (score >= 75) {
            flags.push(`ABUSEIPDB_HIGH_CONFIDENCE: Abuse confidence score ${score}% — IP strongly associated with malicious activity`);
        }
        else if (score >= 25) {
            flags.push(`ABUSEIPDB_MODERATE_RISK: Abuse confidence score ${score}% — IP has abuse reports on record`);
        }
        if (d?.isTor) {
            flags.push('TOR_EXIT_NODE: IP is a known Tor exit node — identity obfuscation in use');
        }
        if (d?.totalReports && d.totalReports > 100) {
            flags.push(`HIGH_REPORT_COUNT: ${d.totalReports} abuse reports from ${d.numDistinctUsers} distinct reporters`);
        }
        const CATEGORIES = {
            3: 'Fraud Orders', 4: 'DDoS Attack', 7: 'Phishing', 8: 'Fraud VoIP',
            10: 'Web Spam', 11: 'Email Spam', 15: 'Hacking', 16: 'SQL Injection',
            17: 'Spoofing', 18: 'Brute Force', 21: 'Web App Attack', 22: 'SSH',
        };
        const recentCategories = new Set();
        for (const report of (d?.reports ?? []).slice(0, 5)) {
            for (const cat of report.categories ?? []) {
                if (CATEGORIES[cat])
                    recentCategories.add(CATEGORIES[cat]);
            }
        }
        return {
            source: 'abuseipdb',
            status: 'ok',
            ip: d?.ipAddress,
            abuse_confidence_score: score,
            total_reports: d?.totalReports ?? 0,
            distinct_reporters: d?.numDistinctUsers ?? 0,
            is_tor: d?.isTor ?? false,
            isp: d?.isp,
            usage_type: d?.usageType,
            country: d?.countryCode,
            last_reported: d?.lastReportedAt ?? null,
            recent_attack_types: Array.from(recentCategories),
            flags,
        };
    }
    catch (err) {
        return { source: 'abuseipdb', status: 'error', error: String(err) };
    }
}
// ──────────────────────────────────────────────────────────────────
// Postcodes.io — UK postcode geolocation + admin district
// Free, no auth, no rate limit (within reason).
// ──────────────────────────────────────────────────────────────────
async function lookupPostcode(postcode) {
    try {
        const clean = postcode.replace(/\s/g, '').toUpperCase();
        const url = `https://api.postcodes.io/postcodes/${encodeURIComponent(clean)}`;
        const res = await fetchWithTimeout(url);
        if (res.status === 404) {
            return { source: 'postcodes_io', status: 'not_found', postcode: clean, note: 'Invalid or non-existent UK postcode' };
        }
        if (!res.ok) {
            return { source: 'postcodes_io', status: 'error', httpStatus: res.status };
        }
        const json = await res.json();
        const r = json.result;
        return {
            source: 'postcodes_io',
            status: 'ok',
            postcode: r?.postcode,
            location: { lat: r?.latitude, lon: r?.longitude },
            district: r?.admin_district,
            county: r?.admin_county,
            country: r?.country,
            constituency: r?.parliamentary_constituency,
            flags: [],
        };
    }
    catch (err) {
        return { source: 'postcodes_io', status: 'error', error: String(err) };
    }
}
// ──────────────────────────────────────────────────────────────────
// Phone analysis — format validation + UK carrier inference
//
// NOTE: BT Phone Directory has no public API.
// 118500.co.uk / 192.com / Truecaller = no programmatic access.
// This returns format analysis + Ofcom carrier range data only.
// For subscriber identity: contact BT Business or Action Fraud.
// ──────────────────────────────────────────────────────────────────
async function analysePhone(query) {
    const raw = query.replace(/[\s\-().]/g, '');
    const ukMobile = /^(\+44|0)7[0-9]{9}$/.test(raw);
    const ukLandline = /^(\+44|0)[1-9][0-9]{8,9}$/.test(raw);
    const ukPremium = /^(\+44|0)9[0-9]{9}$/.test(raw);
    const ukNonGeo = /^(\+44|0)3[0-9]{9}$/.test(raw);
    const ukFreephone = /^(\+44|0)800[0-9]{6,7}$/.test(raw);
    const flags = [];
    let numberType = 'UNKNOWN';
    let carrier_note = 'BT phone directory lookup not available — no public API exists';
    if (ukMobile) {
        numberType = 'UK_MOBILE';
        const prefix7 = raw.replace(/^\+44/, '0').slice(1, 4);
        if (['740', '741', '742', '743', '744', '745', '746'].includes(prefix7))
            carrier_note = 'Likely: O2 UK';
        else if (['770', '771', '772', '773', '774', '775', '776', '777', '778', '779'].includes(prefix7))
            carrier_note = 'Likely: Vodafone UK';
        else if (['730', '731', '732', '733', '734', '735', '736', '737', '738', '739'].includes(prefix7))
            carrier_note = 'Likely: EE UK';
        else if (['750', '751', '752', '753', '754', '755', '756', '757', '758', '759'].includes(prefix7))
            carrier_note = 'Likely: Three UK';
        else
            carrier_note = 'UK mobile — carrier not determinable without live lookup';
    }
    else if (ukLandline) {
        numberType = 'UK_LANDLINE';
        carrier_note = 'UK geographic landline — carrier unknown without CNAM lookup';
    }
    else if (ukPremium) {
        numberType = 'UK_PREMIUM_RATE';
        flags.push('PREMIUM_RATE_NUMBER: 09x numbers are premium rate — common in scam callbacks and IRSF fraud');
    }
    else if (ukNonGeo) {
        numberType = 'UK_NON_GEOGRAPHIC';
        flags.push('NON_GEOGRAPHIC: 03x numbers cannot be traced to a location — commonly used in impersonation scams');
    }
    else if (ukFreephone) {
        numberType = 'UK_FREEPHONE';
    }
    else if (/^\+/.test(raw)) {
        numberType = 'INTERNATIONAL';
        const highRiskPrefixes = ['+225', '+232', '+234', '+233', '+256', '+27', '+380', '+7', '+90'];
        if (highRiskPrefixes.some(p => raw.startsWith(p))) {
            flags.push(`INTERNATIONAL_HIGH_RISK_PREFIX: ${raw.slice(0, 4)} is a frequently spoofed or fraud-associated international prefix`);
        }
    }
    else {
        flags.push('INVALID_FORMAT: Does not match recognised UK or international number format');
    }
    const numverifyKey = process.env.NUMVERIFY_API_KEY;
    let numverifyResult = null;
    if (numverifyKey) {
        try {
            const nvUrl = `http://apilayer.net/api/validate?access_key=${numverifyKey}&number=${encodeURIComponent(raw)}&country_code=GB`;
            const nvRes = await fetchWithTimeout(nvUrl);
            if (nvRes.ok) {
                const nvJson = await nvRes.json();
                numverifyResult = {
                    valid: nvJson.valid,
                    carrier: nvJson.carrier,
                    line_type: nvJson.line_type,
                    location: nvJson.location,
                    country: nvJson.country_name,
                };
                if (nvJson.line_type === 'premium_rate') {
                    flags.push('NUMVERIFY_PREMIUM_RATE_CONFIRMED: Live validation confirms premium rate line');
                }
            }
        }
        catch {
            // Non-fatal
        }
    }
    return {
        source: 'phone_analysis',
        status: 'ok',
        raw_input: query,
        normalised: raw,
        number_type: numberType,
        carrier_note,
        bt_directory: 'NOT_AVAILABLE — BT has no public phone directory API. For subscriber ID: contact BT Business or Action Fraud.',
        numverify: numverifyResult ?? (numverifyKey ? { status: 'error' } : { status: 'not_configured', note: 'Set NUMVERIFY_API_KEY — free at numverify.com' }),
        flags,
    };
}
// ──────────────────────────────────────────────────────────────────
// Email analysis — format, disposable check, MX records, HIBP breach
//
// No key needed for:
//   - Format validation
//   - Disposable check (mailcheck.ai — free, no key)
//   - MX lookup (Cloudflare DNS-over-HTTPS — free, no key)
//   - Domain intel (reuses existing RDAP, VirusTotal, PhishTank)
//
// HIBP requires a paid key (£3.50/mo): haveibeenpwned.com/API/Key
// ──────────────────────────────────────────────────────────────────
async function analyseEmail(query) {
    const flags = [];
    const emailRe = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRe.test(query)) {
        return {
            source: 'email_analysis',
            status: 'invalid',
            error: 'Not a valid email address format',
            flags: ['INVALID_FORMAT'],
        };
    }
    const [localPart, domain] = query.toLowerCase().split('@');
    // Disposable email detection via mailcheck.ai (free, no key)
    let disposable = false;
    let disposableSource = 'unknown';
    try {
        const mcRes = await fetchWithTimeout(`https://api.mailcheck.ai/domain/${encodeURIComponent(domain)}`);
        if (mcRes.ok) {
            const mcJson = await mcRes.json();
            disposable = mcJson.disposable ?? false;
            if (disposable) {
                flags.push(`DISPOSABLE_EMAIL: Domain ${domain} is a known disposable/temporary email provider — high fraud risk`);
            }
            if (!mcJson.mx) {
                flags.push(`NO_MX_RECORD: Domain ${domain} has no mail exchange records — this address cannot receive email`);
            }
            disposableSource = 'mailcheck.ai';
        }
    }
    catch {
        // Non-fatal
    }
    // MX record check via Cloudflare DNS-over-HTTPS (free, no key)
    let hasMX = false;
    try {
        const dnsRes = await fetchWithTimeout(`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(domain)}&type=MX`, { headers: { Accept: 'application/dns-json' } });
        if (dnsRes.ok) {
            const dnsJson = await dnsRes.json();
            hasMX = (dnsJson.Answer ?? []).some(r => r.type === 15);
            if (!hasMX && !flags.some(f => f.includes('NO_MX_RECORD'))) {
                flags.push(`NO_MX_RECORD: Domain ${domain} has no MX records — cannot receive email`);
            }
        }
    }
    catch {
        // Non-fatal
    }
    // Random-looking local parts = likely auto-generated fraud accounts
    const randomPattern = /^[a-z0-9]{12,}$/.test(localPart) && !/^(info|support|admin|hello|contact|sales|noreply)/.test(localPart);
    if (randomPattern) {
        flags.push(`RANDOM_LOCAL_PART: Local part "${localPart}" appears auto-generated — common in fraud account creation`);
    }
    // HIBP breach check (optional — requires paid key)
    const hibpKey = process.env.HIBP_API_KEY;
    let hibpResult = null;
    if (hibpKey) {
        try {
            const hibpRes = await fetchWithTimeout(`https://haveibeenpwned.com/api/v3/breachedaccount/${encodeURIComponent(query)}?truncateResponse=false`, { headers: { 'hibp-api-key': hibpKey, 'User-Agent': 'INVESTiGATOR/1.0' } });
            if (hibpRes.status === 404) {
                hibpResult = { breached: false, breach_count: 0 };
            }
            else if (hibpRes.ok) {
                const breaches = await hibpRes.json();
                hibpResult = {
                    breached: true,
                    breach_count: breaches.length,
                    breaches: breaches.map(b => ({
                        name: b.Name,
                        date: b.BreachDate,
                        data_exposed: b.DataClasses,
                    })),
                };
                if (breaches.length > 0) {
                    flags.push(`HIBP_BREACH: Email appears in ${breaches.length} known data breach(es) — credentials likely compromised`);
                }
            }
        }
        catch {
            // Non-fatal
        }
    }
    // Domain intelligence — reuses existing lookup functions
    const [rdap, vt, phish] = await Promise.allSettled([
        lookupRDAP(domain),
        lookupVirusTotal(domain, 'domain'),
        lookupPhishTank(`https://${domain}`),
    ]);
    const domainSources = [
        rdap.status === 'fulfilled' ? rdap.value : { source: 'rdap_whois', status: 'error' },
        vt.status === 'fulfilled' ? vt.value : { source: 'virustotal', status: 'error' },
        phish.status === 'fulfilled' ? phish.value : { source: 'phishtank', status: 'error' },
    ];
    for (const s of domainSources) {
        if (s && typeof s === 'object' && 'flags' in s) {
            flags.push(...s.flags);
        }
    }
    return {
        source: 'email_analysis',
        status: 'ok',
        email: query,
        local_part: localPart,
        domain,
        disposable,
        disposable_check: disposableSource,
        has_mx: hasMX,
        hibp: hibpResult ?? (hibpKey
            ? { status: 'error' }
            : { status: 'not_configured', note: 'Set HIBP_API_KEY — haveibeenpwned.com/API/Key (paid, £3.50/mo)' }),
        domain_intelligence: domainSources,
        flags,
    };
}
// ══════════════════════════════════════════════════════════════════
// ROUTE HANDLER
// POST /investigate
// Body: { type: 'company'|'fca'|'domain'|'ip'|'postcode'|'phone'|'email', query: string }
// ══════════════════════════════════════════════════════════════════
const router = (0, express_1.Router)();
router.post('/', investigateLimiter, async (req, res) => {
    const parsed = InvestigateSchema.safeParse(req.body);
    if (!parsed.success) {
        res.status(400).json({
            error: parsed.error.issues[0].message,
            valid_types: QUERY_TYPES,
            _legal: terms_1.LEGAL.API_FOOTER,
        });
        return;
    }
    const { type, query } = parsed.data;
    checkInputCanary(query, type, req);
    try {
        let sources;
        const allFlags = [];
        switch (type) {
            case 'company': {
                const [ch, fca, fcaWarn, disq, charity] = await Promise.allSettled([
                    lookupCompaniesHouse(query),
                    lookupFCA(query),
                    lookupFCAWarning(query),
                    lookupDisqualifiedDirectors(query),
                    lookupCharityCommission(query),
                ]);
                const chResult = ch.status === 'fulfilled' ? ch.value : { source: 'companies_house', status: 'error' };
                const fcaResult = fca.status === 'fulfilled' ? fca.value : { source: 'fca_register', status: 'error' };
                const warnResult = fcaWarn.status === 'fulfilled' ? fcaWarn.value : { source: 'fca_warning_list', status: 'error' };
                const disqResult = disq.status === 'fulfilled' ? disq.value : { source: 'ch_disqualified', status: 'error' };
                const charResult = charity.status === 'fulfilled' ? charity.value : { source: 'charity_commission', status: 'error' };
                sources = [chResult, fcaResult, warnResult, disqResult, charResult];
                if (chResult && typeof chResult === 'object' && 'results' in chResult) {
                    const r = chResult;
                    const firstCo = r.results?.[0];
                    if (firstCo?.company_number) {
                        const [officers, charges, filings] = await Promise.allSettled([
                            lookupCompanyOfficers(firstCo.company_number),
                            lookupCompanyCharges(firstCo.company_number),
                            lookupFilingHistory(firstCo.company_number),
                        ]);
                        if (officers.status === 'fulfilled' && officers.value) {
                            sources = [...sources, { source: 'company_officers', status: 'ok', data: officers.value, flags: [] }];
                        }
                        if (charges.status === 'fulfilled' && charges.value) {
                            sources = [...sources, charges.value];
                        }
                        if (filings.status === 'fulfilled' && filings.value) {
                            sources = [...sources, filings.value];
                            if (filings.value.flags?.length)
                                allFlags.push(...filings.value.flags);
                        }
                    }
                }
                for (const s of sources) {
                    if (s && typeof s === 'object' && 'flags' in s) {
                        allFlags.push(...s.flags);
                    }
                }
                break;
            }
            case 'fca': {
                const [reg, warn] = await Promise.allSettled([
                    lookupFCA(query),
                    lookupFCAWarning(query),
                ]);
                sources = [
                    reg.status === 'fulfilled' ? reg.value : { source: 'fca_register', status: 'error' },
                    warn.status === 'fulfilled' ? warn.value : { source: 'fca_warning_list', status: 'error' },
                ];
                for (const s of sources) {
                    if (s && typeof s === 'object' && 'flags' in s) {
                        allFlags.push(...s.flags);
                    }
                }
                break;
            }
            case 'domain': {
                const clean = query.replace(/^https?:\/\//i, '').split('/')[0];
                const [rdap, vt, phish, urlscan] = await Promise.allSettled([
                    lookupRDAP(clean),
                    lookupVirusTotal(clean, 'domain'),
                    lookupPhishTank(query),
                    lookupURLScan(clean),
                ]);
                sources = [
                    rdap.status === 'fulfilled' ? rdap.value : { source: 'rdap_whois', status: 'error' },
                    vt.status === 'fulfilled' ? vt.value : { source: 'virustotal', status: 'error' },
                    phish.status === 'fulfilled' ? phish.value : { source: 'phishtank', status: 'error' },
                    urlscan.status === 'fulfilled' ? urlscan.value : { source: 'urlscan', status: 'error' },
                ];
                for (const s of sources) {
                    if (s && typeof s === 'object' && 'flags' in s) {
                        allFlags.push(...s.flags);
                    }
                }
                break;
            }
            case 'ip': {
                const [ipinfo, ripe, vt, abuse] = await Promise.allSettled([
                    lookupIPInfo(query),
                    lookupRIPE(query),
                    lookupVirusTotal(query, 'ip'),
                    lookupAbuseIPDB(query),
                ]);
                sources = [
                    ipinfo.status === 'fulfilled' ? ipinfo.value : { source: 'ipinfo', status: 'error' },
                    ripe.status === 'fulfilled' ? ripe.value : { source: 'ripe_rdap', status: 'error' },
                    vt.status === 'fulfilled' ? vt.value : { source: 'virustotal', status: 'error' },
                    abuse.status === 'fulfilled' ? abuse.value : { source: 'abuseipdb', status: 'error' },
                ];
                for (const s of sources) {
                    if (s && typeof s === 'object' && 'flags' in s) {
                        allFlags.push(...s.flags);
                    }
                }
                break;
            }
            case 'postcode': {
                const result = await lookupPostcode(query);
                sources = [result];
                break;
            }
            case 'phone': {
                const result = await analysePhone(query);
                sources = [result];
                if (result && typeof result === 'object' && 'flags' in result) {
                    allFlags.push(...result.flags);
                }
                break;
            }
            case 'email': {
                const result = await analyseEmail(query);
                sources = [result];
                if (result && typeof result === 'object' && 'flags' in result) {
                    allFlags.push(...result.flags);
                }
                break;
            }
            case 'person': {
                const result = await lookupPersonByName(query);
                sources = [result];
                if (result && typeof result === 'object' && 'flags' in result) {
                    allFlags.push(...result.flags);
                }
                break;
            }
            default:
                sources = [];
        }
        res.json({
            query,
            type,
            risk_flags: allFlags,
            flag_count: allFlags.length,
            sources,
            fair_use: terms_1.LEGAL.FAIR_USE_POLICY,
            _legal: terms_1.LEGAL.API_FOOTER,
        });
    }
    catch (err) {
        console.error('[investigate] handler error:', err);
        res.status(500).json({ error: 'Internal server error', _legal: terms_1.LEGAL.API_FOOTER });
    }
});
exports.default = router;

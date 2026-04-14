"use strict";
/**
 * INVESTiGATOR — Canary Alert System
 *
 * Fires when a known canary sentinel value is queried.
 * Canary values are planted in outputs/reports — if they arrive
 * back as input queries, it means data leaked from the system.
 *
 * CANARY INDEX — keep these private, never publish externally
 * ─────────────────────────────────────────────────────────────
 *   CANARY-INV-CO-001     Fictitious company name/number sentinel
 *   CANARY-INV-PHONE-001  Ofcom reserved test number (+447700900001)
 *   CANARY-INV-DOMAIN-001 Canary domain (sv-canary.co.uk)
 *   CANARY-INV-IP-001     RFC 5737 TEST-NET address (192.0.2.254)
 *   CANARY-INV-POST-001   Fictitious UK postcode (SV1 0CV)
 *   CANARY-INV-EMAIL-001  Canary email (canary@sv-canary.co.uk)
 *
 * ALERT SETUP
 * ─────────────────────────────────────────────────────────────
 *   Set CANARY_WEBHOOK_URL in .env to receive instant alerts.
 *   Discord, Slack, and most webhook services are supported.
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.alertCanaryTripped = alertCanaryTripped;
/**
 * alertCanaryTripped — fires when a canary input value is detected.
 * Logs to console always. Posts to webhook if CANARY_WEBHOOK_URL is set.
 */
async function alertCanaryTripped(canaryRef, context) {
    const alert = {
        severity: 'CRITICAL',
        event: 'CANARY_TRIPPED',
        canaryRef,
        timestamp: new Date().toISOString(),
        context,
    };
    // Always log locally
    console.error('[CANARY ALERT]', JSON.stringify(alert));
    // Webhook alert — set CANARY_WEBHOOK_URL in .env
    const webhookUrl = process.env.CANARY_WEBHOOK_URL;
    if (webhookUrl) {
        try {
            await fetch(webhookUrl, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(alert),
            });
        }
        catch (err) {
            console.error('[CANARY] Webhook delivery failed:', err);
        }
    }
}

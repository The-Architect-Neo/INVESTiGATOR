"use strict";
/**
 * INVESTiGATOR — Corporate Intelligence Acquisition
 *
 * Fraud investigation API. Fans out to multiple free public
 * intelligence sources and returns structured results with risk flags.
 *
 * POST /investigate  — main lookup endpoint (7 types, 17 sources)
 * GET  /health       — Railway health check
 *
 * All API keys are optional — sources degrade gracefully if not set.
 * See .env.example for the full list.
 */
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = __importDefault(require("express"));
const express_rate_limit_1 = __importDefault(require("express-rate-limit"));
const path_1 = __importDefault(require("path"));
const dotenv_1 = __importDefault(require("dotenv"));
const investigate_1 = __importDefault(require("./routes/investigate"));
dotenv_1.default.config();
const app = (0, express_1.default)();
const PORT = process.env.PORT ?? 3000;
// Trust Railway's reverse proxy — required for rate limiting to use real client IP
app.set('trust proxy', 1);
// ── Middleware ───────────────────────────────────────────────────────
app.use(express_1.default.json({ limit: '50kb' }));
// Global rate limit — 100 requests per 15 minutes per IP
const globalLimiter = (0, express_rate_limit_1.default)({
    windowMs: 15 * 60 * 1000,
    max: 100,
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: 'Too many requests. Slow down and try again shortly.' },
});
app.use(globalLimiter);
// ── Routes ───────────────────────────────────────────────────────────
app.use('/investigate', investigate_1.default);
app.get('/health', (_req, res) => {
    res.json({ status: 'ok', service: 'investigator', ts: new Date().toISOString() });
});
app.get('/', (_req, res) => {
    res.sendFile(path_1.default.resolve(__dirname, '..', 'index.html'));
});
// ── Start ────────────────────────────────────────────────────────────
app.listen(PORT, () => {
    console.log(`[INVESTiGATOR] Running on port ${PORT}`);
});

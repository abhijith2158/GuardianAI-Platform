import sqlite3

from flask import Flask, jsonify, request

from guardian_sdk import enable
from guardian_sdk.monitor import GuardianBlocked


enable(service_name="python-test-app", log_path="security.log", mode="block")

app = Flask(__name__)


@app.get("/")
def index():
    return "Python Vulnerable App Running"


@app.post("/login")
def login():
    username = request.json.get("username", "") if request.is_json else request.form.get("username", "")
    password = request.json.get("password", "") if request.is_json else request.form.get("password", "")

    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE users (username TEXT, password TEXT)")
    cursor = conn.cursor()

    query = (
        "SELECT * FROM users WHERE username = '"
        + username
        + "' AND password = '"
        + password
        + "'"
    )

    try:
        cursor.execute(query)
    except GuardianBlocked as exc:
        return jsonify({"error": f"Blocked by GuardianAI: {exc}"}), 403

    return jsonify({"status": "attempted", "queryExecuted": query})


if __name__ == "__main__":
    print("Python Vulnerable App starting on http://0.0.0.0:5000")
    app.run(host="0.0.0.0", port=5000)

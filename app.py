from flask import Flask, render_template, request, redirect, url_for, session, send_file
from werkzeug.security import check_password_hash, generate_password_hash
import pandas as pd
import os

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "ims_secret_key")

# Dummy in-memory data store (you can replace with SQLite later)
SCAN_LOGS = [
    {"target": "192.168.1.1", "type": "Quick Scan", "result": "No threat found", "date": "2025-07-08"},
    {"target": "example.com", "type": "APT Pattern Scan", "result": "Threat Detected", "date": "2025-07-08"},
]
from dotenv import load_dotenv
load_dotenv()
API_KEYS = {
    "virustotal": os.getenv("VT_API_KEY"),
    "otx": os.getenv("OTX_API_KEY")
}

ADMIN_PASSWORD_HASH = generate_password_hash("admin123")  # Change this

@app.route("/admin", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        if username == "admin" and check_password_hash(ADMIN_PASSWORD_HASH, password):
            session['admin'] = True
            return redirect(url_for("dashboard"))
    return render_template("login.html")

@app.route("/dashboard")
def dashboard():
    if not session.get("admin"):
        return redirect(url_for("login"))
    return render_template("dashboard.html", logs=SCAN_LOGS)

@app.route("/export")
def export():
    if not session.get("admin"):
        return redirect(url_for("login"))
    df = pd.DataFrame(SCAN_LOGS)
    df.to_csv("scan_logs.csv", index=False)
    return send_file("scan_logs.csv", as_attachment=True)

@app.route("/apikeys", methods=["GET", "POST"])
def apikeys():
    if not session.get("admin"):
        return redirect(url_for("login"))
    if request.method == "POST":
        API_KEYS["virustotal"] = request.form.get("virustotal")
        API_KEYS["otx"] = request.form.get("otx")
    return render_template("apikeys.html", keys=API_KEYS)

@app.route("/logout")
def logout():
    session.pop("admin", None)
    return redirect(url_for("login"))

if __name__ == "__main__":
    import os
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)


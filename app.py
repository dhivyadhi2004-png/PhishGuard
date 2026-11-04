
from flask import Flask, render_template, request, jsonify
from analyzer import analyze_email
from database import create_database, save_email
import sqlite3

app = Flask(__name__)
create_database()

@app.route("/")
def dashboard():
    return render_template("index.html")

@app.route("/history")
def get_history():

    connection = sqlite3.connect("phishguard.db")
    cursor = connection.cursor()

    cursor.execute("""
        SELECT sender, subject, risk_score, verdict, analyzed_at,
               body, urls, keywords, url_warnings,
               sender_warnings, reply_warnings, auth_checks
        FROM email_history
        ORDER BY id DESC
    """)

    records = cursor.fetchall()
    connection.close()

    history = []

    for record in records:
        history.append({
            "sender": record[0],
            "subject": record[1],
            "risk_score": record[2],
            "verdict": record[3],
            "analyzed_at": record[4],
            "body": record[5] or "",
            "urls": (record[6] or "").splitlines(),
            "keywords": (record[7] or "").splitlines(),
            "url_warnings": (record[8] or "").splitlines(),
            "sender_warnings": (record[9] or "").splitlines(),
            "reply_warnings": (record[10] or "").splitlines(),
            "auth_checks": (record[11] or "").splitlines()
        })

    return jsonify(history)


@app.route("/analyze", methods=["POST"])
def analyze_uploaded_email():

    if "email" not in request.files:
        return jsonify({"error": "No email uploaded"}), 400

    file = request.files["email"]

    if not file.filename:
        return jsonify({"error": "No file selected"}), 400

    if not file.filename.lower().endswith(".eml"):
        return jsonify({"error": "Please upload an .eml file"}), 400

    content = file.read()

    if not content:
        return jsonify({"error": "The email file is empty"}), 400

    try:
        results = analyze_email(content)

        save_email(
            results["sender"],
            results["subject"],
            results["risk_score"],
            results["verdict"],
            results["body"],
            results["urls"],
            results["keywords"],
            results["url_warnings"],
            results["sender_warnings"],
            results["reply_warnings"],
            results["auth_checks"]
        )

        return jsonify(results)

    except Exception as error:
        print("Analysis error:", error)
        return jsonify({"error": "Email analysis failed"}), 500


if __name__ == "__main__":
    app.run(debug=True)

from analyzer import analyze_email
from flask import Flask, render_template, request, jsonify

app = Flask(__name__)

@app.route("/")
def dashboard():
    return render_template("index.html")


@app.route("/analyze", methods=["POST"])
def analyze_uploaded_email():

    if "email" not in request.files:
        return jsonify({"error": "No email uploaded"}), 400

    file = request.files["email"]

    if not file.filename:
        return jsonify({"error": "No file selected"}), 400

    if not file.filename.lower().endswith(".eml"):
        return jsonify({"error": "Please upload an .eml file"}), 400

    email_bytes = file.read()

    if not email_bytes:
        return jsonify({"error": "The email file is empty"}), 400

    try:
        results = analyze_email(email_bytes)
        return jsonify(results)

    except Exception as error:
        return jsonify({"error": str(error)}), 500


if __name__ == "__main__":
    app.run(debug=True)
from flask import Flask, render_template, request
import hashlib
import os
import re

app = Flask(__name__)

# ---------------------------------------------------
# Password Strength Checker
# ---------------------------------------------------
def password_strength(password):
    length = len(password)
    score = 0
    notes = []

    if length >= 8: score += 1
    else: notes.append("less than 8 characters")

    if re.search(r"[a-z]", password): score += 1
    else: notes.append("no lowercase letters")

    if re.search(r"[A-Z]", password): score += 1
    else: notes.append("no uppercase letters")

    if re.search(r"[0-9]", password): score += 1
    else: notes.append("no digits")

    if re.search(r"[^A-Za-z0-9]", password): score += 1
    else: notes.append("no special characters")

    strength = {
        0:"Very Weak",1:"Weak",2:"Moderate",
        3:"Good",4:"Strong",5:"Very Strong"
    }[score]

    return score, strength, notes

# ---------------------------------------------------
# File Integrity Checker
# ---------------------------------------------------
def compute_file_hash(file_data, algo="sha256"):
    h = hashlib.new(algo)
    h.update(file_data)
    return h.hexdigest()

# ---------------------------------------------------
# Web Routes
# ---------------------------------------------------
@app.route("/")
def home():
    return render_template("index.html")

@app.route("/check_password", methods=["POST"])
def check_password():
    password = request.form["password"]
    score, strength, notes = password_strength(password)
    return render_template("result.html",
                           title="Password Strength Result",
                           result=f"Strength: {strength} ({score}/5)",
                           notes=notes)

@app.route("/file_hash", methods=["POST"])
def file_hash():
    if "file" not in request.files:
        return "No file uploaded"
    file = request.files["file"]
    data = file.read()
    h = compute_file_hash(data)
    return render_template("result.html",
                           title="File Integrity Result",
                           result=f"SHA-256 Hash: {h}",
                           notes=[])

# ---------------------------------------------------
if __name__ == "__main__":
    app.run(debug=True)

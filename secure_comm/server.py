from flask import Flask, request, jsonify
import os
import json

app = Flask(__name__)

# Simple in-memory store (later SQLite use karenge)
USERS = {}
MESSAGES = {}

# ==============================
# Register Public Key
# ==============================

@app.route("/register", methods=["POST"])
def register():
    data = request.json
    username = data["username"]
    public_key = data["public_key"]

    USERS[username] = public_key
    MESSAGES[username] = []

    return jsonify({"status": "registered"})


# ==============================
# Get Public Key
# ==============================

@app.route("/get_key/<username>", methods=["GET"])
def get_key(username):
    if username in USERS:
        return jsonify({"public_key": USERS[username]})
    return jsonify({"error": "User not found"}), 404


# ==============================
# Send Encrypted Message
# ==============================

@app.route("/send", methods=["POST"])
def send():
    data = request.json
    receiver = data["receiver"]

    if receiver not in MESSAGES:
        return jsonify({"error": "Receiver not found"}), 404

    MESSAGES[receiver].append(data)

    return jsonify({"status": "message stored"})


# ==============================
# Receive Messages
# ==============================

@app.route("/receive/<username>", methods=["GET"])
def receive(username):
    if username not in MESSAGES:
        return jsonify({"error": "User not found"}), 404

    user_messages = MESSAGES[username]
    MESSAGES[username] = []  # Auto clear (basic self-destruct logic)

    return jsonify({"messages": user_messages})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)

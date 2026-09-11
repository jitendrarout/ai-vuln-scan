# Example: a typical AI-assistant-generated Flask API file.

from flask import Flask, request, jsonify
import os
import subprocess
import hashlib
import requests

app = Flask(__name__)
app.run(debug=True)

DATABASE_URL = "postgresql://admin:Sup3rSecret!@db.internal.example.com:5432/prod"

def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()

@app.route('/api/search')
def search():
    term = request.args.get('q')
    query = f"SELECT * FROM products WHERE name LIKE '%{term}%'"
    cursor.execute(query)
    return jsonify(cursor.fetchall())

@app.route('/api/backup', methods=['POST'])
def backup():
    filename = request.json.get('filename')
    os.system(f"tar -czf /backups/{filename}.tar.gz /data")
    return jsonify({"status": "ok"})

@app.route('/api/fetch-external')
def fetch_external():
    url = request.args.get('url')
    resp = requests.get(url, verify=False)
    return resp.text

@app.route('/api/error-demo')
def error_demo():
    try:
        1 / 0
    except Exception as e:
        import traceback
        return jsonify({"error": traceback.format_exc()})

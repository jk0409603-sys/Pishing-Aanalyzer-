from flask import Flask, request, jsonify
from urllib.parse import urlparse
import subprocess
import json

from database import init_db, save_analysis, get_history, get_analysis_by_id

app = Flask(__name__)
init_db()   # app start hote hi table ready ho jaye


def is_valid_url(url):
    if not isinstance(url, str):
        return False
    url = url.strip()
    if len(url) == 0 or len(url) > 2000:
        return False
    if " " in url:
        return False
    parsed = urlparse(url)
    return parsed.scheme in ("http", "https") and bool(parsed.netloc)


@app.route("/")
def home():
    return "Hello, PhishGuard!"


@app.route("/analyze", methods=["POST"])
def analyze():
    data = request.get_json(silent=True)

    if not data or "url" not in data:
        return jsonify({"error": "Send JSON like {\"url\": \"...\"}"}), 400

    url = data["url"]

    if not is_valid_url(url):
        return jsonify({"error": "Invalid URL"}), 400

    url = url.strip()

    result = subprocess.run(
        ["analyzer.exe", url],
        capture_output=True,
        text=True,
        stdin=subprocess.DEVNULL,
        timeout=10
    )

    output = result.stdout
    json_start = output.find("{")
    analysis = json.loads(output[json_start:])

    # database mein save karo
    new_id = save_analysis(url, analysis["risk"], json.dumps(analysis))
    analysis["id"] = new_id

    return jsonify(analysis)


@app.route("/history", methods=["GET"])
def history():
    limit = request.args.get("limit", default=20, type=int)
    if limit < 1 or limit > 100:
        return jsonify({"error": "Limit must be between 1 and 100"}), 400

    return jsonify(get_history(limit))



@app.route("/analysis/<int:analysis_id>", methods=["GET"])
def analysis_detail(analysis_id):
    record = get_analysis_by_id(analysis_id)

    if record is None:
        return jsonify({"error": "Analysis not found"}), 404

    record["result"] = json.loads(record["result"])
    return jsonify(record)


if __name__ == "__main__":
    app.run(debug=True)
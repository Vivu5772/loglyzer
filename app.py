from flask import Flask, request, render_template, jsonify
import os
from loganalysis import analyze_log
from attack_detection import detect_attacks

app = Flask(__name__)

UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)


@app.route("/")
def home():
    return render_template("network-log-uploader.html")


@app.route("/upload", methods=["POST"])
def upload_file():

    # ----------------------------
    # File validation
    # ----------------------------
    if "logfile" not in request.files:
        return jsonify({"status": "error", "message": "No file uploaded"}), 400

    file = request.files["logfile"]

    if file.filename == "":
        return jsonify({"status": "error", "message": "Empty filename"}), 400

    filepath = os.path.join(UPLOAD_FOLDER, file.filename)
    file.save(filepath)

    # ----------------------------
    # Log analysis
    # ----------------------------
    df = analyze_log(filepath)

    if df is None or df.empty:
        return jsonify({
            "status": "error",
            "message": "Unsupported or non-network log format"
        }), 400

    # ----------------------------
    # Table data (limit for UI)
    # ----------------------------
    table_data = df.head(100).astype(str).to_dict(orient="records")



    # ----------------------------
    # Attack detection
    # ----------------------------
    alerts = detect_attacks(df)






    # ----------------------------
    # Chart data (Top source IPs)
    # ----------------------------
    if "src_ip" in df.columns:
        top_ips = df["src_ip"].head(50000).value_counts().head(5)
        labels = [str(ip) for ip in top_ips.index]
        values = [int(v) for v in top_ips.values]
    else:
        labels = []
        values = []

    # ----------------------------
    # Final JSON response
    # ----------------------------
    return jsonify({
        "status": "success",
        "rows": table_data,
        "chart_labels": labels,
        "chart_values": values,
        "alerts": alerts
    })


if __name__ == "__main__":
    app.run(debug=False)

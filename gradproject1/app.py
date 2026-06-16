#!/usr/bin/env python3
import os, sys, json, tempfile, time, urllib.request, urllib.error, re
from pathlib import Path
from flask import Flask, request, jsonify
from flask_cors import CORS
from werkzeug.utils import secure_filename

PROJECT_DIR = Path(__file__).parent
sys.path.insert(0, str(PROJECT_DIR))

from plugins.zigbee_plugin import ZigbeePlugin
from plugins.ble_plugin     import BLEPlugin
from plugins.zwave_plugin   import ZWavePlugin

app = Flask(__name__)
CORS(app)

UPLOAD_FOLDER      = tempfile.mkdtemp()
ALLOWED_EXTENSIONS = {'pcap', 'pcapng'}
_cve_cache         = {}

ALL_PLUGINS = {
    "Zigbee": ZigbeePlugin(),
    "BLE":    BLEPlugin(),
    "Z-Wave": ZWavePlugin(),
}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/api/health', methods=['GET'])
def health():
    return jsonify({"status": "ok", "plugins": list(ALL_PLUGINS.keys())})

@app.route('/api/cve/<cve_id>', methods=['GET'])
def cve_lookup(cve_id):
    cve_id = cve_id.upper().strip()
    if cve_id in _cve_cache:
        return jsonify(_cve_cache[cve_id])
    if not re.match(r'^CVE-\d{4}-\d{4,}$', cve_id):
        return jsonify({"error": "Invalid CVE ID format"}), 400
    try:
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
        req = urllib.request.Request(url, headers={"User-Agent": "SAGE-IoT-Scanner/1.0"})
        with urllib.request.urlopen(req, timeout=8) as resp:
            data = json.loads(resp.read())
        vulns = data.get("vulnerabilities", [])
        if not vulns:
            return jsonify({"error": f"{cve_id} not found in NVD"}), 404
        cve_data = vulns[0].get("cve", {})
        descriptions = cve_data.get("descriptions", [])
        desc_en = next((d["value"] for d in descriptions if d["lang"] == "en"), "No description")
        metrics = cve_data.get("metrics", {})
        score = severity = vector = None
        for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
            if key in metrics and metrics[key]:
                m = metrics[key][0]
                cvss     = m.get("cvssData", {})
                score    = cvss.get("baseScore")
                severity = cvss.get("baseSeverity") or m.get("baseSeverity")
                vector   = cvss.get("vectorString")
                break
        refs      = [r["url"] for r in cve_data.get("references", [])[:3]]
        published = cve_data.get("published", "")[:10]
        result = {"id": cve_id, "description": desc_en, "score": score,
                  "severity": severity, "vector": vector,
                  "published": published, "references": refs}
        _cve_cache[cve_id] = result
        return jsonify(result)
    except urllib.error.URLError as e:
        return jsonify({"error": f"NVD API unavailable: {str(e)}"}), 503
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/scan', methods=['POST'])
def scan():
    if 'file' not in request.files:
        return jsonify({"error": "No file provided"}), 400
    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "No file selected"}), 400
    if not allowed_file(file.filename):
        return jsonify({"error": "Only .pcap and .pcapng files allowed"}), 400
    selected_raw = request.form.get("protocols", "")
    selected = [p.strip() for p in selected_raw.split(",") if p.strip()] if selected_raw else list(ALL_PLUGINS.keys())
    plugins_to_run = [ALL_PLUGINS[n] for n in selected if n in ALL_PLUGINS]
    if not plugins_to_run:
        return jsonify({"error": "No valid protocols selected"}), 400
    filename  = secure_filename(file.filename)
    pcap_path = os.path.join(UPLOAD_FOLDER, filename)
    file.save(pcap_path)
    results = []
    start_time = time.time()
    try:
        for plugin in plugins_to_run:
            if plugin.supports(pcap_path):
                try:
                    results.append(plugin.scan(pcap_path))
                except Exception as e:
                    results.append({"protocol": plugin.name, "error": str(e), "vulns": []})
            else:
                # البروتوكول مش موجود في الـ pcap — أرجع إحصائيات فارغة
                empty_stats = {}
                if plugin.name == "Zigbee":
                    empty_stats = {"encrypted":0,"total":0,"unencrypted":0,"zigbee":0}
                elif plugin.name == "BLE":
                    empty_stats = {"advertisements":0,"ble":0,"control_packets":0,"data_packets":0,"encrypted":0,"total":0,"unencrypted":0}
                elif plugin.name == "Z-Wave":
                    empty_stats = {"s0_frames":0,"s2_frames":0,"total_packets":0,"unencrypted":0,"zwave_frames":0}
                results.append({
                    "protocol": plugin.name,
                    "vulns": [],
                    "statistics": empty_stats,
                    "topology": {"nodes": [], "edges": []}
                })
    finally:
        try: os.unlink(pcap_path)
        except: pass
    return jsonify({"filename": filename, "scan_time": round(time.time()-start_time,2),
                    "protocols": selected, "results": results})

if __name__ == '__main__':
    print("\n  IoT Scanner Backend")
    print(f"  Plugins: {list(ALL_PLUGINS.keys())}")
    print(f"  Running on http://0.0.0.0:5000\n")
    app.run(debug=True, port=5000, host="0.0.0.0")

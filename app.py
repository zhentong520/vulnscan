# -*- coding: utf-8 -*-
"""VulnScan — 简单漏洞扫描系统 API。

运行:  venv/Scripts/python app.py   (默认 127.0.0.1:5330)
"""
from flask import Flask, jsonify, request, send_from_directory

import scanner

app = Flask(__name__, static_folder="static", static_url_path="")


@app.get("/")
def index():
    return send_from_directory(app.static_folder, "index.html")


@app.post("/api/scans")
def create_scan():
    body = request.get_json(force=True, silent=True) or {}
    try:
        scan = scanner.create_scan(body.get("target", "").strip(),
                                   body.get("engines", []))
        return jsonify({"ok": True, "scan": scan}), 201
    except ValueError as e:
        return jsonify({"ok": False, "error": str(e)}), 400


@app.get("/api/scans")
def list_scans():
    return jsonify({"scans": scanner.list_scans()})


@app.get("/api/scans/<scan_id>")
def scan_detail(scan_id):
    scan = scanner.get_scan(scan_id)
    if not scan:
        return jsonify({"ok": False, "error": "not found"}), 404
    return jsonify({"ok": True, "scan": scan})


@app.get("/api/scans/<scan_id>/report")
def scan_report(scan_id):
    p = scanner.scan_paths(scan_id)["report"]
    if not p.exists():
        return jsonify({"ok": False, "error": "report not ready"}), 404
    return app.response_class(p.read_text(encoding="utf-8"), mimetype="text/markdown")


@app.get("/api/scans/<scan_id>/findings")
def scan_findings(scan_id):
    if not scanner.get_scan(scan_id):
        return jsonify({"ok": False, "error": "not found"}), 404
    q = request.args
    fs = scanner.get_findings(
        scan_id,
        severity=q.get("severity") or None,
        ftype=q.get("type") or None,
        engine=q.get("engine") or None,
        keyword=q.get("q") or None,
        include_fp=(q.get("include_fp", "1") != "0"),
        limit=int(q.get("limit", 500)))
    if fs is None:
        return jsonify({"ok": False, "error": "findings not ready"}), 404
    return jsonify({"ok": True, "count": len(fs), "findings": fs})


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5330, debug=False, threaded=True)

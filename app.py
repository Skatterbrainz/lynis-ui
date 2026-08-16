#!/usr/bin/env python3
"""
Lynis Findings Web Dashboard

A small local-only Flask app that shows the latest Lynis scan findings in a
browser table and lets you select findings to exempt (accept as risk). An
"Exempt" action appends skip-test= lines to /etc/lynis/custom.prf so those
tests are excluded from future scans.

Run with: sudo python3 app.py   (see run.sh)
Then open: http://localhost:5000

This app is intended for local, single-user use only. It binds to the
loopback interface only and is not meant to be exposed on any network.
"""
import json
import os
import sys

from flask import Flask, jsonify, render_template, request

import lynis_report_parser as lrp


def resource_path(*parts):
    """
    Resolve a path to a bundled resource. Works identically when running
    from source and when frozen into a PyInstaller onefile executable
    (which unpacks bundled data files under sys._MEIPASS at runtime).
    """
    base_path = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base_path, *parts)


KNOWLEDGE_PATH = resource_path("lynis_knowledge.json")

app = Flask(
    __name__,
    template_folder=resource_path("templates"),
    static_folder=resource_path("static"),
)


def load_knowledge():
    try:
        with open(KNOWLEDGE_PATH, "r") as fh:
            return json.load(fh)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/findings")
def api_findings():
    knowledge = load_knowledge()
    try:
        data = lrp.build_findings_list(knowledge=knowledge)
    except FileNotFoundError as exc:
        return jsonify({"error": str(exc)}), 500
    except PermissionError:
        return jsonify(
            {
                "error": (
                    "Permission denied reading the Lynis report. "
                    "Run this app with sudo (./run.sh)."
                )
            }
        ), 500
    return jsonify(data)


@app.route("/api/exempt", methods=["POST"])
def api_exempt():
    payload = request.get_json(silent=True) or {}
    test_ids = payload.get("test_ids") or []
    reason = payload.get("reason") or "Accepted risk"

    if not isinstance(test_ids, list) or not test_ids:
        return jsonify({"error": "No test_ids provided."}), 400

    # Basic sanity filter: Lynis test IDs look like ABCD-1234.
    clean_ids = [tid for tid in test_ids if isinstance(tid, str) and "-" in tid]
    if not clean_ids:
        return jsonify({"error": "No valid test_ids provided."}), 400

    try:
        added, already_exempt = lrp.append_exemptions(clean_ids, reason)
    except PermissionError:
        return jsonify(
            {
                "error": (
                    "Permission denied writing /etc/lynis/custom.prf. "
                    "Run this app with sudo (./run.sh)."
                )
            }
        ), 500

    return jsonify(
        {
            "added": added,
            "already_exempt": already_exempt,
            "custom_profile_path": lrp.CUSTOM_PROFILE_PATH,
        }
    )


@app.route("/api/unexempt", methods=["POST"])
def api_unexempt():
    payload = request.get_json(silent=True) or {}
    test_ids = payload.get("test_ids") or []

    if not isinstance(test_ids, list) or not test_ids:
        return jsonify({"error": "No test_ids provided."}), 400

    clean_ids = [tid for tid in test_ids if isinstance(tid, str) and "-" in tid]
    if not clean_ids:
        return jsonify({"error": "No valid test_ids provided."}), 400

    try:
        removed = lrp.remove_exemptions(clean_ids)
    except PermissionError:
        return jsonify(
            {
                "error": (
                    "Permission denied writing /etc/lynis/custom.prf. "
                    "Run this app with sudo (./run.sh)."
                )
            }
        ), 500

    return jsonify({"removed": removed, "custom_profile_path": lrp.CUSTOM_PROFILE_PATH})


if __name__ == "__main__":
    # Loopback only. Do not set debug=True or bind to a non-loopback host.
    app.run(host="localhost", port=5000, debug=False)

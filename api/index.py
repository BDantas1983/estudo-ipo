import json
import os
import sys

# Garante que os módulos locais da raiz possam ser importados pelo Vercel Serverless
root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if root_dir not in sys.path:
    sys.path.insert(0, root_dir)

import ipo_dashboard
from http.server import BaseHTTPRequestHandler

class handler(BaseHTTPRequestHandler):
    def do_GET(self):
        try:
            data = ipo_dashboard.get_fresh_analysis()
            payload = json.dumps(data, ensure_ascii=False).encode("utf-8")

            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(payload)
        except Exception as e:
            self.send_response(500)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.end_headers()
            self.wfile.write(json.dumps({"error": str(e)}).encode("utf-8"))

    def do_POST(self):
        try:
            content_length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_length).decode("utf-8", errors="ignore")
            req = json.loads(body) if body else {}

            fname = req.get("filename", "soc_network_telemetry.csv")
            ftype = req.get("type", "csv_network")

            target_path = os.path.join(root_dir, fname)
            if os.path.exists(target_path):
                ipo_dashboard.CURRENT_DATASET["name"] = fname
                ipo_dashboard.CURRENT_DATASET["type"] = ftype
                ipo_dashboard.CURRENT_DATASET["filepath"] = target_path

            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(json.dumps({"status": "ok"}).encode("utf-8"))
        except Exception as e:
            self.send_response(500)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"error": str(e)}).encode("utf-8"))

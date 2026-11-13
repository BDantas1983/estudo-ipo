from http.server import HTTPServer, BaseHTTPRequestHandler
import csv
import json
import os
from datetime import datetime, timezone

VALID_USER = "admin"
VALID_PASS = "S0c_Secur3_2026!"
LOGS_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "soc_network_telemetry.csv")

CSV_FIELDNAMES = [
    "timestamp", "source_ip", "source_hostname", "source_user",
    "destination_ip", "destination_port", "domain", "protocol",
    "http_method", "status_code", "bytes_sent", "bytes_received",
    "user_agent", "action", "is_malicious", "matched_ioc",
    "threat_actor", "mitre_technique"
]

def log_telemetry_event(client_ip, user, status_code, bytes_sent, bytes_received, user_agent):
    file_exists = os.path.isfile(LOGS_FILE)
    timestamp_utc = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    is_failure = status_code == 401

    row = {
        "timestamp": timestamp_utc,
        "source_ip": client_ip,
        "source_hostname": "WS-ATTACKER-SIM" if client_ip == "127.0.0.1" else "EXT-HOST",
        "source_user": user or "desconhecido",
        "destination_ip": "127.0.0.1",
        "destination_port": "8080",
        "domain": "localhost",
        "protocol": "TCP",
        "http_method": "POST",
        "status_code": str(status_code),
        "bytes_sent": str(bytes_sent),
        "bytes_received": str(bytes_received),
        "user_agent": user_agent or "Python-urllib",
        "action": "ALLOW",
        "is_malicious": str(is_failure),
        "matched_ioc": "",
        "threat_actor": "",
        "mitre_technique": "T1110.001" if is_failure else ""
    }

    with open(LOGS_FILE, "a", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_FIELDNAMES)
        if not file_exists:
            writer.writeheader()
        writer.writerow(row)

class LoginHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        if self.path == "/login":
            content_length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_length).decode("utf-8")
            
            try:
                data = json.loads(body)
                user = data.get("username", "")
                password = data.get("password", "")
            except Exception:
                user, password = "", ""

            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            client_ip = self.headers.get("X-Forwarded-For", self.client_address[0])
            user_agent = self.headers.get("User-Agent", "Python-urllib")

            if user == VALID_USER and password == VALID_PASS:
                # Login com sucesso
                response_payload = b'{"status": "success", "message": "Autenticado"}'
                self.send_response(200)
                self.end_headers()
                self.wfile.write(response_payload)
                log_telemetry_event(client_ip, user, 200, content_length, len(response_payload), user_agent)
                print(f"[{timestamp}] [200 OK] Sucesso: {user} vindo de {client_ip}")
            else:
                # Falha de autenticação
                response_payload = b'{"status": "error", "message": "Credenciais invalidas"}'
                self.send_response(401)
                self.end_headers()
                self.wfile.write(response_payload)
                log_telemetry_event(client_ip, user, 401, content_length, len(response_payload), user_agent)
                print(f"[{timestamp}] [401 FALHA] Tentativa falha: usuario='{user}' senha='{password}' de {client_ip}")
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        # Desativa o log padrao verboso do BaseHTTPRequestHandler para manter a saida limpa
        return

if __name__ == "__main__":
    server = HTTPServer(("127.0.0.1", 8080), LoginHandler)
    print("[*] Servidor alvo ativo em http://127.0.0.1:8080/login")
    print("[*] Pressione Ctrl+C para encerrar.\n")
    server.serve_forever()
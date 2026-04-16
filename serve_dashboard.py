#!/usr/bin/env python3
"""Simple web server for Agent Gateway Enforcer dashboard"""

import http.server
import socketserver
import json
import os
from datetime import datetime

PORT = 8080

class DashboardHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        # API endpoints
        if self.path == '/api/status':
            self.send_json({
                "status": "healthy",
                "uptime": "Running",
                "version": "0.1.0",
                "backend": "demo"
            })
        elif self.path == '/api/config':
            self.send_json({
                "gateways": [
                    {"address": "api.openai.com:443", "enabled": True},
                    {"address": "api.anthropic.com:443", "enabled": True}
                ],
                "file_access": {
                    "enabled": False,
                    "allowed_paths": []
                }
            })
        elif self.path == '/api/events':
            self.send_json({
                "events": [
                    {
                        "id": "1",
                        "type": "network",
                        "action": "allowed",
                        "timestamp": datetime.now().isoformat(),
                        "details": "Connection to api.openai.com:443"
                    },
                    {
                        "id": "2",
                        "type": "file",
                        "action": "blocked",
                        "timestamp": datetime.now().isoformat(),
                        "details": "Access to /etc/shadow denied"
                    }
                ]
            })
        elif self.path == '/api/metrics':
            self.send_json({
                "network": {
                    "blocked_total": 42,
                    "allowed_total": 1234
                },
                "file": {
                    "blocked_total": 15,
                    "allowed_total": 567
                },
                "timestamp": datetime.now().isoformat()
            })
        else:
            # Serve static files
            super().do_GET()

    def send_json(self, data):
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(json.dumps(data).encode())

    def log_message(self, format, *args):
        # Custom logging
        print(f"[{datetime.now().strftime('%H:%M:%S')}] {format % args}")

# Change to static directory
os.chdir('/Users/aryehlev/Documents/agent-gateway-enforcer/agent-gateway-enforcer-core/static')

print("╔══════════════════════════════════════════════════════════╗")
print("║   🌐 Agent Gateway Enforcer Dashboard Server            ║")
print("╚══════════════════════════════════════════════════════════╝")
print()
print(f"📊 Dashboard: http://localhost:{PORT}")
print(f"📁 Serving from: {os.getcwd()}")
print()
print("API Endpoints:")
print(f"  • GET http://localhost:{PORT}/api/status")
print(f"  • GET http://localhost:{PORT}/api/config")
print(f"  • GET http://localhost:{PORT}/api/events")
print(f"  • GET http://localhost:{PORT}/api/metrics")
print()
print("Press Ctrl+C to stop...")
print()

with socketserver.TCPServer(("", PORT), DashboardHandler) as httpd:
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n\n👋 Shutting down...")

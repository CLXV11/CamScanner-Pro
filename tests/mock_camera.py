#!/usr/bin/env python3
"""Mock IP camera for testing CAM-SEC Scanner. Localhost ONLY.

Serves HTTP endpoints that mimic a Hikvision camera with known issues:
- Server banner: Hikvision-DS/1.0  (single header, unlike BaseHTTPRequestHandler default)
- CVE-2017-7921: /Security/users returns unauthenticated XML user list
- CVE-2017-7925: /System/configurationFile returns a large binary blob
- /.env exposure with secret-looking keys
- ONVIF GetDeviceInformation SOAP response (POST)
"""
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 18899

class MockCam(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"
    def log_message(self, *a): pass
    def _send(self, code, body=b"", server=None):
        self.send_response_only(code)  # avoid default Server/Date duplication
        if server: self.send_header("Server", server)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def do_GET(self):
        p = self.path.split("?")[0]
        if p == "/":
            self._send(200, b'<html><script>var model = "DS-2CD2143G2";</script>'
                             b'<body>hikvision login page</body></html>',
                       server="Hikvision-DS/1.0")
        elif p == "/Security/users":
            self._send(200, b'<?xml version="1.0"?><userList><user><id>1</id>'
                             b'<userName>admin</userName><userID>1</userID></user></userList>',
                       server="Hikvision-DS/1.0")
        elif p == "/System/configurationFile":
            self._send(200, b"\x00\x01\x02" * 800, server="Hikvision-DS/1.0")
        elif p == "/.env":
            self._send(200, b"APP_KEY=base64:abc123zz\nDB_PASSWORD=hunter2secret\n")
        else:
            self._send(404, b"not found")
    def do_POST(self):
        if self.path.split("?")[0] == "/onvif/device_service":
            self._send(200,
                b'<s:Envelope><s:Body><tds:GetDeviceInformationResponse>'
                b'<tds:Manufacturer>Hikvision</tds:Manufacturer>'
                b'<tds:Model>DS-2CD2143G2-I</tds:Model>'
                b'<tds:FirmwareVersion>V5.5.160 build 190228</tds:FirmwareVersion>'
                b'</tds:GetDeviceInformationResponse></s:Body></s:Envelope>')

if __name__ == "__main__":
    HTTPServer(("127.0.0.1", PORT), MockCam).serve_forever()

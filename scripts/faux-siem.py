#!/usr/bin/env python3
"""Faux SIEM pour le banc d'essai de la diffusion (J9).

faux-siem.py http <port> <fichier>  : reçoit Elastic _bulk, Splunk HEC, OTLP et webhook ;
                                       consigne chaque requête (chemin, en-têtes utiles, corps)
                                       en une ligne JSON.
faux-siem.py tcp <port> <fichier>   : reçoit du syslog TCP à trames préfixées par leur
                                       longueur (RFC 6587) ; une ligne par message.
"""
import json
import socketserver
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

MODE, PORT, TRACE = sys.argv[1], int(sys.argv[2]), sys.argv[3]


def consigner(ligne):
    with open(TRACE, "a") as f:
        f.write(ligne + "\n")


class Http(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        self.send_response(200)
        self.end_headers()

    def do_POST(self):
        corps = self.rfile.read(int(self.headers.get("content-length", 0))).decode()
        entetes = {k.lower(): v for k, v in self.headers.items() if k.lower().startswith(("x-aplomb", "authorization", "content-type"))}
        consigner(json.dumps({"chemin": self.path, "entetes": entetes, "corps": corps}))
        reponse = {"errors": False, "items": []} if self.path.endswith("_bulk") else {"text": "Success", "code": 0}
        octets = json.dumps(reponse).encode()
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(octets)))
        self.end_headers()
        self.wfile.write(octets)


class Syslog(socketserver.StreamRequestHandler):
    def handle(self):
        while True:
            longueur = b""
            while True:
                c = self.rfile.read(1)
                if not c:
                    return
                if c == b" ":
                    break
                longueur += c
            consigner(self.rfile.read(int(longueur)).decode())


if MODE == "http":
    ThreadingHTTPServer(("127.0.0.1", PORT), Http).serve_forever()
else:
    socketserver.ThreadingTCPServer.allow_reuse_address = True
    socketserver.ThreadingTCPServer(("127.0.0.1", PORT), Syslog).serve_forever()

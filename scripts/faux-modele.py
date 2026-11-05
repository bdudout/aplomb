#!/usr/bin/env python3
"""Faux modèle pour le banc d'essai : imite l'API Messages en flux (SSE).

Un appel sur deux demande un outil Bash (identifiant toolu_banc_<n>), l'autre répond par
du texte. Chaque requête reçue est consignée (chemin, corps, en-têtes d'authentification) dans
le fichier passé en second argument, pour vérifier ce que le proxy d'Aplomb transmet.
Usage : faux-modele.py <port> <fichier-des-requetes>
"""
import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT, TRACE = int(sys.argv[1]), sys.argv[2]
appels = 0


def sse(evenements):
    return "".join(f"event: {e['type']}\ndata: {json.dumps(e)}\n\n" for e in evenements).encode()


class Modele(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_POST(self):
        global appels
        appels += 1
        corps = self.rfile.read(int(self.headers.get("content-length", 0))).decode(errors="replace")
        with open(TRACE, "a") as f:
            f.write(json.dumps({"chemin": self.path, "corps": corps, "x-api-key": self.headers.get("x-api-key"),
                                "authorization": self.headers.get("authorization"),
                                "anthropic-beta": self.headers.get("anthropic-beta")}) + "\n")
        debut = {"type": "message_start", "message": {"usage": {"input_tokens": 100, "cache_read_input_tokens": 20}}}
        if appels % 2:
            bloc = {"type": "tool_use", "id": f"toolu_banc_{appels}", "name": "Bash", "input": {}}
        else:
            bloc = {"type": "text", "text": "fini"}
        corps = sse([debut, {"type": "content_block_start", "index": 0, "content_block": bloc},
                     {"type": "message_delta", "usage": {"output_tokens": 7}}, {"type": "message_stop"}])
        self.send_response(200)
        self.send_header("content-type", "text/event-stream")
        self.send_header("content-length", str(len(corps)))
        self.end_headers()
        self.wfile.write(corps)


ThreadingHTTPServer(("127.0.0.1", PORT), Modele).serve_forever()

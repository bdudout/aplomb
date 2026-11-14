#!/usr/bin/env python3
"""Faux moniteur externe pour le banc d'essai (contrat v1 des moniteurs d'Aplomb).

POST /v1/avis reçoit {"contrat": 1, "intention", "outil", "action": {verbe, ressource,
contexte}, "historique", ["entree"]} et rend {"niveau", "score", "motif"} :
« SUSPECT » dans la requête → suspect ; « CRITIQUE » → critique (plafonné par Aplomb) ;
« PANNE » → erreur 500 ; « LENT » → répond après le délai ; sinon conforme.
Chaque requête est consignée dans le fichier passé en second argument.
Usage : faux-moniteur.py <port> <fichier-des-requetes>
"""
import json
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT, TRACE = int(sys.argv[1]), sys.argv[2]


class Moniteur(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        self.send_response(200)
        self.end_headers()

    def do_POST(self):
        brut = self.rfile.read(int(self.headers.get("content-length", 0))).decode()
        with open(TRACE, "a") as f:
            f.write(brut + "\n")
        if "PANNE" in brut:
            self.send_response(500)
            self.end_headers()
            return
        if "LENT" in brut:
            time.sleep(2)
        niveau = "critique" if "CRITIQUE" in brut else "suspect" if "SUSPECT" in brut else "conforme"
        corps = json.dumps({"niveau": niveau, "score": 0.9 if niveau != "conforme" else 0.1, "motif": f"faux moniteur : {niveau}"}).encode()
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(corps)))
        self.end_headers()
        self.wfile.write(corps)


ThreadingHTTPServer(("127.0.0.1", PORT), Moniteur).serve_forever()

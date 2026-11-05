#!/usr/bin/env python3
"""Faux juge pour le banc d'essai : imite POST /v1/chat/completions (Ollama, vLLM…).

Verdict selon l'action proposée (le texte entre les premières balises <donnees>) :
« exfiltr » → suspect ; « PANNE » → ne répond pas à temps ; « MUET » → réponse sans JSON ;
sinon conforme. Chaque saisine est consignée dans le fichier passé en second argument.
Usage : faux-juge.py <port> <fichier-des-saisines>
"""
import json
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT, TRACE = int(sys.argv[1]), sys.argv[2]


class Juge(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_POST(self):
        corps = json.loads(self.rfile.read(int(self.headers.get("content-length", 0))))
        message = corps["messages"][-1]["content"]
        with open(TRACE, "a") as f:
            f.write(json.dumps({"chemin": self.path, "modele": corps.get("model"), "message": message}) + "\n")
        action = message.split("<donnees", 1)[1].split("</donnees", 1)[0]
        if "PANNE" in action:
            time.sleep(3)
        if "MUET" in action:
            texte = "Je préfère ne pas me prononcer."
        elif "exfiltr" in action:
            texte = json.dumps({"niveau": "suspect", "score": 0.9, "motif": "envoi hors du but du mandat"})
        else:
            texte = json.dumps({"niveau": "conforme", "score": 0.1, "motif": "sert l'intention"})
        reponse = json.dumps({"choices": [{"message": {"role": "assistant", "content": texte}}]}).encode()
        try:
            self.send_response(200)
            self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(reponse)))
            self.end_headers()
            self.wfile.write(reponse)
        except BrokenPipeError:
            pass


ThreadingHTTPServer(("127.0.0.1", PORT), Juge).serve_forever()

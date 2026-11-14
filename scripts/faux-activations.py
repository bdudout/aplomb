#!/usr/bin/env python3
"""Faux serveur d'activations pour le banc d'essai (moniteur interne, J7), sans modèle.

Imite l'API qu'un vrai serveur d'activations rend à Aplomb (voir docs/SONDE.md) :
  POST /v1/activations  {"modele", "couche", "contexte", "texte", "appel", "score"}
  → {"modele", "couche", "activations": [512 flottants]}   (ou {"score": x} si "score": true)

Les « activations » sont un sac de mots haché (mots et paires de mots du texte, signés,
normalisés) : une représentation du texte, pas celle d'un modèle. La sonde de test entraînée
dessus est donc un classifieur linéaire de texte. Elle sert à éprouver l'interface, la
chaîne de décision et la mesure sur le banc ; elle ne dit rien de ce qu'une vraie sonde
verrait dans un vrai modèle. « PANNE » dans le texte : la réponse arrive trop tard.

Usage :
  faux-activations.py serveur <port> [fichier-des-requetes]
  faux-activations.py entrainer <exemples.jsonl> <poids.json>
    (exemples : une ligne JSON {"texte": ..., "trompeur": true|false} par exemple)
Python seul, aucune dépendance.
"""
import hashlib
import json
import math
import re
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

DIMENSION = 512
MODELE = "faux-activations"


def mots(texte):
    return re.findall(r"[a-zàâäçéèêëîïôöùûüÿœ']+", texte.lower())


def activations(texte):
    """Sac de mots et de paires de mots, haché sur DIMENSION composantes signées, normé."""
    v = [0.0] * DIMENSION
    m = [x.strip("'") for x in mots(texte) if len(x.strip("'")) > 2]
    for jeton in m + [a + " " + b for a, b in zip(m, m[1:])]:
        h = hashlib.sha256(jeton.encode()).digest()
        i = int.from_bytes(h[:4], "little") % DIMENSION
        v[i] += 1.0 if h[4] & 1 else -1.0
    n = math.sqrt(sum(x * x for x in v)) or 1.0
    return [x / n for x in v]


def sigmoide(z):
    return 1.0 / (1.0 + math.exp(-max(-30.0, min(30.0, z))))


def entrainer(exemples, sortie, epoques=3000, pas=2.0, l2=0.0005):
    """Régression logistique (descente de gradient), classes équilibrées."""
    lignes = [json.loads(l) for l in open(exemples) if l.strip()]
    X = [activations(e["texte"]) for e in lignes]
    y = [1.0 if e["trompeur"] else 0.0 for e in lignes]
    positifs = sum(y)
    poids_classe = {1.0: len(y) / (2 * positifs), 0.0: len(y) / (2 * (len(y) - positifs))}
    w, b = [0.0] * DIMENSION, 0.0
    for _ in range(epoques):
        gw, gb = [0.0] * DIMENSION, 0.0
        for x, t in zip(X, y):
            e = (sigmoide(sum(a * c for a, c in zip(w, x)) + b) - t) * poids_classe[t]
            for i, c in enumerate(x):
                if c:
                    gw[i] += e * c
            gb += e
        w = [a - pas * (g / len(X) + l2 * a) for a, g in zip(w, gw)]
        b -= pas * gb / len(X)
    justes = sum((sigmoide(sum(a * c for a, c in zip(w, x)) + b) >= 0.5) == (t == 1.0) for x, t in zip(X, y))
    json.dump({
        "nom": "tromperie",
        "description": "Sonde de TEST : régression logistique sur le faux serveur d'activations (sac de mots haché), "
                       "entraînée sur scripts/sonde-entrainement.jsonl. Ne vaut que pour le banc.",
        "modele": MODELE, "couche": 0, "poids": [round(a, 6) for a in w], "biais": round(b, 6),
    }, open(sortie, "w"))
    print(f"{len(X)} exemples ({int(positifs)} trompeurs) ; exactitude à l'entraînement : {justes}/{len(X)} ; poids : {sortie}")


class Serveur(BaseHTTPRequestHandler):
    trace = None

    def log_message(self, *args):
        pass

    def do_GET(self):
        self.repondre({"modele": MODELE, "dimension": DIMENSION})

    def do_POST(self):
        corps = json.loads(self.rfile.read(int(self.headers.get("content-length", 0))))
        if Serveur.trace:
            with open(Serveur.trace, "a") as f:
                f.write(json.dumps(corps, ensure_ascii=False) + "\n")
        if "PANNE" in corps.get("texte", ""):
            time.sleep(3)
        # Le contexte (intention du mandat) est le même pour toutes les actions : il ne change
        # pas le score d'une sonde linéaire ; seul le texte produit est représenté.
        self.repondre({"modele": MODELE, "couche": corps.get("couche") or 0, "activations": activations(corps.get("texte", ""))})

    def repondre(self, objet):
        r = json.dumps(objet).encode()
        try:
            self.send_response(200)
            self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(r)))
            self.end_headers()
            self.wfile.write(r)
        except BrokenPipeError:
            pass


if __name__ == "__main__":
    if len(sys.argv) >= 3 and sys.argv[1] == "serveur":
        Serveur.trace = sys.argv[3] if len(sys.argv) > 3 else None
        ThreadingHTTPServer(("127.0.0.1", int(sys.argv[2])), Serveur).serve_forever()
    elif len(sys.argv) == 4 and sys.argv[1] == "entrainer":
        entrainer(sys.argv[2], sys.argv[3])
    else:
        sys.exit(__doc__)

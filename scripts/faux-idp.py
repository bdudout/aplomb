#!/usr/bin/env python3
"""Faux fournisseur d'identité OpenID Connect pour le banc d'essai (J10).

faux-idp.py <port> <profil.json>
  GET  /auth   : renvoie aussitôt vers redirect_uri avec un code (pas d'écran de connexion) ;
  POST /token  : rend un id_token (JWT non signé : Aplomb l'authentifie par le lien direct
                 avec le point de jeton, OIDC Core § 3.1.3.7) pour le profil du fichier :
                 {"email": …, "groups": […], "amr": […]}, relu à chaque connexion.
Vérifie le défi PKCE (S256) et le client.
"""
import base64
import hashlib
import json
import secrets
import sys
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT, PROFIL = int(sys.argv[1]), sys.argv[2]
EMETTEUR = f"http://127.0.0.1:{PORT}"
CODES = {}


def b64(o):
    return base64.urlsafe_b64encode(o).rstrip(b"=").decode()


class Idp(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        u = urllib.parse.urlparse(self.path)
        q = dict(urllib.parse.parse_qsl(u.query))
        if u.path != "/auth":
            self.send_response(200)
            self.end_headers()
            return
        code = secrets.token_urlsafe(16)
        CODES[code] = (q["nonce"], q["code_challenge"], q["client_id"], q["redirect_uri"])
        self.send_response(302)
        self.send_header("location", q["redirect_uri"] + "?" + urllib.parse.urlencode({"code": code, "state": q["state"]}))
        self.end_headers()

    def do_POST(self):
        corps = self.rfile.read(int(self.headers.get("content-length", 0))).decode()
        f = dict(urllib.parse.parse_qsl(corps))
        nonce, defi, client, retour = CODES.pop(f.get("code"), (None,) * 4)
        attendu = b64(hashlib.sha256(f.get("code_verifier", "").encode()).digest())
        if nonce is None or defi != attendu or f.get("client_id") != client or f.get("redirect_uri") != retour or f.get("client_secret") != "secret-sso-du-banc":
            self.send_response(400)
            self.end_headers()
            return
        profil = json.load(open(PROFIL))
        t = int(time.time())
        charge = {"iss": EMETTEUR, "aud": client, "exp": t + 300, "iat": t, "nonce": nonce, "sub": "u-" + profil["email"], **profil}
        jwt = b64(b'{"alg":"none"}') + "." + b64(json.dumps(charge).encode()) + ".sig"
        octets = json.dumps({"id_token": jwt, "token_type": "Bearer"}).encode()
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(octets)))
        self.end_headers()
        self.wfile.write(octets)


ThreadingHTTPServer(("127.0.0.1", PORT), Idp).serve_forever()

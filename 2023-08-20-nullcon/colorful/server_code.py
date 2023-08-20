from flask import Flask, redirect, request, after_this_request
import os
import json
import secrets
from Crypto.Cipher import AES

app = Flask(__name__)

if not os.path.exists("secret"):
    with open("secret", "wb") as f:
        f.write(os.urandom(16))

app.secret_key = open("secret", "rb").read()

class SessionHandler(object):

    def __init__(self, k):
        self.k = k

    def set(self, r,p, key=None, val=None):
        session = self.get_session(r)
        if key and val:
            session[key] = val
        session = self.set_session(r, session)
        p.set_cookie("session", session, path='/')
        return session

    def set_session(self, r, s):
        c = ""
        for k in sorted(s.keys()):
            c+= f"{k}={s[k]}&"
        return self._c(c)

    def get(self, r, p):
        return self.get_session(r)

    def get_session(self, r):
        session = r.cookies.get("session", None)
        if not session:
            session = self.new_session(r)
        return self.parse(self._d(session))

    def parse(self, c):
        d = {}
        if c is None:
            return d
        for p in c.split("&"):
            try:
                k,v = p.split("=")
                if not k in d:
                    d[k]=v
            except:
                pass
        return d

    def new_session(self, r):
        id = secrets.token_hex(4)
        c = f"_id={id}&admin=0&color=ffff00&"
        return self._c(c)

    def _c(self, v):
        try:
            v = v.encode()
            while len(v) % 16 != 0:
                v += b'\x41' 
            return AES.new(self.k,1).encrypt(v).hex()
        except:
            return None

    def _d(self, v):
        try:
            return 
AES.new(self.k,1).decrypt(bytearray.fromhex(v)).decode()
        except:
            return None

app.session_handler = SessionHandler(app.secret_key)

@app.route("/color/", methods=['POST','GET'])
def change_color(color):

    @after_this_request
    def sc(response):
        app.session_handler.set(request, response,"color",color)
        return response
    return redirect("/")

@app.route("/")
def index():
    code = open(__file__).read()
    session = app.session_handler.get(request,None)
    color = session['color']

    if session['admin'] == '1':
        return open("FLAG").read()

    @after_this_request
    def sc(response):
        app.session_handler.set(request,response)
        return response

    return f"{code}"

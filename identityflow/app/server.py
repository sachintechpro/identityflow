"""Minimal educational demo HTTP API. Do not use as a production identity service."""
from __future__ import annotations
import json,os
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit
from .security import IdentityService,AuthError,DEMO_PROFILES,SESSION_TTL_SECONDS

HOME=Path(__file__).resolve().parents[1]/'web'/'index.html'
SERVICE=IdentityService()
MAX_BODY=12000
class Handler(BaseHTTPRequestHandler):
    def respond(self,status,payload,mime='application/json',cookie=None,head=False):
        body=(json.dumps(payload).encode() if mime=='application/json' else payload if isinstance(payload,bytes) else str(payload).encode())
        self.send_response(status)
        for k,v in {'Content-Type':mime+'; charset=utf-8','Content-Length':str(len(body)),
                    'Cache-Control':'no-store','X-Content-Type-Options':'nosniff','X-Frame-Options':'DENY',
                    'Referrer-Policy':'no-referrer','Content-Security-Policy':"default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; object-src 'none'; base-uri 'none'"}.items():self.send_header(k,v)
        if cookie is not None:
            secure='; Secure' if os.getenv('RENDER') or os.getenv('COOKIE_SECURE')=='1' else ''
            self.send_header('Set-Cookie',f'if_session={cookie}; HttpOnly; SameSite=Strict; Path=/; Max-Age={SESSION_TTL_SECONDS if cookie else 0}{secure}')
        self.end_headers()
        if not head:self.wfile.write(body)
    def token(self):
        for part in self.headers.get('Cookie','').split(';'):
            k,sep,v=part.strip().partition('=')
            if sep and k=='if_session':return v
        return None
    def body(self):
        try:size=int(self.headers.get('Content-Length','0'))
        except ValueError:raise ValueError('Invalid request size')
        if not 1<=size<=MAX_BODY:raise ValueError('JSON request must be 1–12000 bytes')
        if self.headers.get('Content-Type','').split(';')[0].strip().lower()!='application/json':raise ValueError('Content-Type must be application/json')
        try:data=json.loads(self.rfile.read(size))
        except (UnicodeDecodeError,json.JSONDecodeError):raise ValueError('Invalid JSON')
        if not isinstance(data,dict):raise ValueError('JSON object expected')
        return data
    def route(self,method,head=False):
        path=urlsplit(self.path).path
        try:
            if path=='/' and method=='GET':return self.respond(200,HOME.read_bytes(),'text/html',head=head)
            if path=='/api/health' and method=='GET':return self.respond(200,{'status':'ok','mode':'simulated-iam'},head=head)
            if path=='/api/demo-users' and method=='GET':return self.respond(200,[{'username':u,'role':v[1]} for u,v in DEMO_PROFILES.items()],head=head)
            # Cross-site forms cannot add the custom header. This is a demo safeguard, not complete CSRF hardening.
            if method=='POST' and self.headers.get('X-IdentityFlow-Demo')!='1':
                return self.respond(403,{'error':'Demo request header required'})
            if path=='/api/login' and method=='POST':
                d=self.body();result=SERVICE.login(d.get('username'),d.get('password'))
                token=result.pop('session',None)
                return self.respond(200,result,cookie=token)
            if path=='/api/mfa/verify' and method=='POST':
                d=self.body();result=SERVICE.verify_mfa(d.get('challenge'),d.get('code'))
                token=result.pop('session')
                return self.respond(200,result,cookie=token)
            if path=='/api/recover-username' and method=='POST':return self.respond(200,SERVICE.recover_username(self.body().get('email')))
            if path=='/api/request-reset' and method=='POST':return self.respond(200,SERVICE.request_reset(self.body().get('email')))
            if path=='/api/reset-password' and method=='POST':
                d=self.body();return self.respond(200,SERVICE.reset_password(d.get('token'),d.get('password')))
            if path=='/api/logout' and method=='POST':
                SERVICE.logout(self.token());return self.respond(200,{'ok':True},cookie='')
            if path.startswith('/api/'):
                user=SERVICE.authenticate(self.token())
                if path=='/api/me' and method=='GET':return self.respond(200,SERVICE.status(user),head=head)
                if path=='/api/mfa/enroll' and method=='POST':return self.respond(200,SERVICE.enroll_mfa(user))
                if path=='/api/projects' and method=='GET':return self.respond(200,SERVICE.list_projects(user),head=head)
                if path=='/api/projects' and method=='POST':return self.respond(201,SERVICE.add_project(user,self.body().get('name')))
                if path=='/api/users' and method=='GET':return self.respond(200,SERVICE.list_users(user),head=head)
                if path=='/api/audit' and method=='GET':return self.respond(200,SERVICE.audit(user),head=head)
            return self.respond(404,{'error':'Not found'},head=head)
        except AuthError as e:return self.respond(e.status,{'error':str(e)},head=head)
        except ValueError as e:return self.respond(400,{'error':str(e)},head=head)
        except Exception:return self.respond(500,{'error':'Internal server error'},head=head)
    def do_GET(self):self.route('GET')
    def do_HEAD(self):self.route('GET',head=True)
    def do_POST(self):self.route('POST')

if __name__=='__main__':
    port=int(os.environ.get('PORT',8000))
    print('IdentityFlow listening on port '+str(port),flush=True)
    ThreadingHTTPServer(('0.0.0.0',port),Handler).serve_forever()

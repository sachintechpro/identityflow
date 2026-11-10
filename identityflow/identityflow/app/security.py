"""In-memory educational IAM simulator. NOT an IdP or production authentication system."""
from __future__ import annotations
import hashlib, hmac, secrets, threading, time
from collections import deque
from dataclasses import dataclass

ROLES = {'viewer': {'projects:read'}, 'editor': {'projects:read','projects:write'}, 'admin': {'projects:read','projects:write','audit:read','users:read'}}
SESSION_TTL_SECONDS = 20 * 60
RESET_TTL = 10 * 60
MFA_TTL = 3 * 60
LOCK_SECONDS = 5 * 60
MAX_FAILURES = 5
DEMO_PROFILES = {
    'alex.viewer': ('Alex Morgan','viewer','alex.viewer@example.test'),
    'sam.editor': ('Sam Rivera','editor','sam.editor@example.test'),
    'jordan.admin': ('Jordan Lee','admin','jordan.admin@example.test'),
}
DEMO_PASSWORD = 'DemoPass!2026'

@dataclass(frozen=True)
class Identity:
    username: str
    display_name: str
    role: str

class AuthError(ValueError):
    def __init__(self, message='Authentication failed', status=401):
        super().__init__(message); self.status=status

def password_hash(password, salt=None):
    salt = salt or secrets.token_bytes(16)
    hashed = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 180_000)
    return salt.hex() + ':' + hashed.hex()

def password_matches(password, encoded):
    salt, expected = encoded.split(':',1)
    candidate = hashlib.pbkdf2_hmac('sha256', password.encode(), bytes.fromhex(salt), 180_000)
    return hmac.compare_digest(candidate, bytes.fromhex(expected))

def valid_password(password):
    return isinstance(password,str) and 12 <= len(password) <= 128 and any(c.islower() for c in password) and any(c.isupper() for c in password) and any(c.isdigit() for c in password) and any(not c.isalnum() for c in password)

class IdentityService:
    def __init__(self, clock=None):
        self.clock=clock or time.time
        self.lock=threading.RLock()
        self.users={}
        for username,(display,role,email) in DEMO_PROFILES.items():
            initial=password_hash(DEMO_PASSWORD)
            self.users[username]={'identity':Identity(username,display,role),'email':email,
                                  'password':initial,'history':[initial], 'failures':0,'locked_until':0,
                                  'mfa':False, 'recovery':set()}
        self.sessions={}; self.pending={}; self.reset_tokens={}; self.audit_log=deque(maxlen=250)
        self.projects=[{'id':1,'name':'Customer Portal Modernization','status':'Active'},
                       {'id':2,'name':'API Integration Rollout','status':'Planning'}]
        self.next_id=3

    def event(self,actor,action,outcome,resource=''):
        self.audit_log.appendleft({'timestamp':int(self.clock()),'actor':actor,'action':action,'outcome':outcome,'resource':resource})

    def _revoke(self, username):
        for token,(identity,_) in list(self.sessions.items()):
            if identity.username==username: self.sessions.pop(token,None)
        for token,(name,_,_) in list(self.pending.items()):
            if name==username: self.pending.pop(token,None)

    def _session(self, username):
        identity=self.users[username]['identity']; token=secrets.token_urlsafe(32)
        self.sessions[token]=(identity,self.clock()+SESSION_TTL_SECONDS)
        self.event(username,'login','allowed')
        return {'session':token,'username':username,'display_name':identity.display_name,
                'role':identity.role,'permissions':sorted(ROLES[identity.role]),'ttl_seconds':SESSION_TTL_SECONDS}

    def login(self, username, password):
        with self.lock:
            profile=self.users.get(username) if isinstance(username,str) else None
            if not profile or not isinstance(password,str):
                self.event('unknown','login','denied'); raise AuthError('Invalid username or password')
            if self.clock()<profile['locked_until']:
                self.event(username,'login_locked','denied');raise AuthError('Account temporarily locked',423)
            if not password_matches(password,profile['password']):
                profile['failures']+=1; self.event(username,'login','denied')
                if profile['failures']>=MAX_FAILURES:
                    profile['locked_until']=self.clock()+LOCK_SECONDS
                    self.event(username,'account_locked','denied')
                    raise AuthError('Account temporarily locked',423)
                raise AuthError('Invalid username or password')
            profile['failures']=0;profile['locked_until']=0
            if profile['mfa']:
                challenge=secrets.token_urlsafe(24); code=f'{secrets.randbelow(1000000):06d}'
                self.pending[challenge]=(username, hashlib.sha256(code.encode()).hexdigest(),self.clock()+MFA_TTL)
                self.event(username,'mfa_challenge','issued')
                return {'mfa_required':True,'challenge':challenge,'demo_code':code,'ttl_seconds':MFA_TTL}
            return self._session(username)

    def verify_mfa(self, challenge, code):
        with self.lock:
            entry=self.pending.get(challenge)
            if not entry:raise AuthError('Invalid MFA challenge')
            username,digest,expiry=entry
            if self.clock()>=expiry:
                self.pending.pop(challenge,None);self.event(username,'mfa','expired');raise AuthError('MFA challenge expired')
            provided=hashlib.sha256(str(code).encode()).hexdigest()
            profile=self.users[username]
            is_recovery=provided in profile['recovery']
            if not hmac.compare_digest(provided,digest) and not is_recovery:
                self.event(username,'mfa','denied');raise AuthError('Invalid verification code')
            self.pending.pop(challenge,None)
            if is_recovery:profile['recovery'].remove(provided)
            self.event(username,'mfa','allowed')
            return self._session(username)

    def authenticate(self,token):
        with self.lock:
            record=self.sessions.get(token) if isinstance(token,str) else None
            if not record:raise AuthError('No valid session')
            identity,expiry=record
            if self.clock()>=expiry:
                self.sessions.pop(token,None);self.event(identity.username,'session_expired','denied')
                raise AuthError('Session expired')
            return identity

    def logout(self,token):
        with self.lock:
            record=self.sessions.pop(token,None)
            if record:self.event(record[0].username,'logout','allowed')

    def recover_username(self,email):
        # Identical public response for known and unknown emails: demonstration delivery only.
        with self.lock:
            matches=[name for name,profile in self.users.items() if profile['email'].lower()==str(email).strip().lower()]
            self.event('recovery','forgot_username','requested')
            return {'message':'If the email matches a demo account, recovery instructions would be sent.',
                    'demo_delivery':matches}  # NEVER expose this in a real recovery endpoint.

    def request_reset(self, email):
        with self.lock:
            username=next((u for u,v in self.users.items() if v['email'].lower()==str(email).strip().lower()),None)
            token=None
            if username:
                raw=secrets.token_urlsafe(32); token=raw
                self.reset_tokens[hashlib.sha256(raw.encode()).hexdigest()]=(username,self.clock()+RESET_TTL)
            self.event('recovery','forgot_password','requested')
            return {'message':'If the email matches a demo account, reset instructions would be sent.',
                    'demo_token':token}  # Display only in the explicitly labeled simulator.

    def reset_password(self,token,new_password):
        with self.lock:
            digest=hashlib.sha256(str(token).encode()).hexdigest()
            entry=self.reset_tokens.get(digest)
            if not entry:raise AuthError('Invalid or already used reset token',400)
            username,expiry=entry
            if self.clock()>=expiry:
                self.reset_tokens.pop(digest,None);raise AuthError('Reset token expired',400)
            if not valid_password(new_password):raise ValueError('Password needs 12+ characters with uppercase, lowercase, number and symbol.')
            p=self.users[username]
            if any(password_matches(new_password,old) for old in p['history'][-3:]):
                raise ValueError('Cannot reuse the last three passwords')
            self.reset_tokens.pop(digest,None)
            new_hash=password_hash(new_password)
            p['password']=new_hash;p['history'].append(new_hash);p['failures']=0;p['locked_until']=0
            self._revoke(username)
            self.event(username,'password_reset','allowed')
            return {'ok':True,'message':'Password reset. Existing sessions revoked.'}

    def enroll_mfa(self,identity):
        with self.lock:
            p=self.users[identity.username]
            if p['mfa']:raise ValueError('MFA is already enabled')
            p['mfa']=True
            codes=[secrets.token_hex(5).upper() for _ in range(3)]
            p['recovery']={hashlib.sha256(code.encode()).hexdigest() for code in codes}
            self.event(identity.username,'mfa_enrolled','allowed')
            return {'enabled':True,'demo_recovery_codes':codes,'message':'Save the one-time recovery codes. They will not be shown again.'}

    def status(self,identity):
        with self.lock:
            p=self.users[identity.username]
            return {'username':identity.username,'display_name':identity.display_name,'role':identity.role,
                    'permissions':sorted(ROLES[identity.role]),'mfa_enabled':p['mfa'],
                    'session_ttl_seconds':SESSION_TTL_SECONDS}

    def check(self,identity,permission,resource=''):
        allowed=permission in ROLES[identity.role]
        with self.lock:self.event(identity.username,permission,'allowed' if allowed else 'denied',resource)
        if not allowed:raise AuthError(f'Permission denied: {permission}',403)

    def list_projects(self,identity):
        self.check(identity,'projects:read','/api/projects')
        with self.lock:return [dict(p) for p in self.projects]

    def add_project(self,identity,name):
        self.check(identity,'projects:write','/api/projects')
        if not isinstance(name,str) or not 3<=len(name.strip())<=80:raise ValueError('Project name must be 3–80 characters')
        with self.lock:
            p={'id':self.next_id,'name':name.strip(),'status':'Planning'}
            self.next_id+=1;self.projects.append(p);self.event(identity.username,'project_create','allowed',str(p['id']))
            return dict(p)

    def audit(self,identity):
        self.check(identity,'audit:read','/api/audit')
        with self.lock:return list(self.audit_log)

    def list_users(self,identity):
        self.check(identity,'users:read','/api/users')
        with self.lock:return [{'username':u,'display_name':v['identity'].display_name,'role':v['identity'].role,'mfa_enabled':v['mfa']} for u,v in self.users.items()]

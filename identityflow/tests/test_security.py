import unittest
from app.security import IdentityService,AuthError,ROLES,DEMO_PASSWORD,valid_password

class IdentityTests(unittest.TestCase):
    def setUp(self):
        self.now=1000
        self.s=IdentityService(clock=lambda:self.now)
    def sign_in(self,u='alex.viewer',pwd=DEMO_PASSWORD):
        r=self.s.login(u,pwd)
        self.assertNotIn('mfa_required',r)
        return r['session'],self.s.authenticate(r['session'])
    def reset_token(self,username='alex.viewer'):
        return self.s.request_reset(username+'@example.test')['demo_token']
    def test_roles(self):
        self.assertEqual(ROLES['viewer'],{'projects:read'})
    def test_initial_password_rules(self):
        self.assertTrue(valid_password(DEMO_PASSWORD));self.assertFalse(valid_password('abc'))
    def test_login_correct(self):
        token,u=self.sign_in();self.assertEqual(u.role,'viewer');self.assertGreater(len(token),30)
    def test_invalid_password(self):
        with self.assertRaises(AuthError):self.s.login('alex.viewer','bad')
    def test_unknown_user(self):
        with self.assertRaises(AuthError):self.s.login('unknown',DEMO_PASSWORD)
    def test_lockout_after_five(self):
        for i in range(5):
            with self.assertRaises(AuthError) as e:self.s.login('alex.viewer','bad')
        self.assertEqual(e.exception.status,423)
        with self.assertRaises(AuthError):self.s.login('alex.viewer',DEMO_PASSWORD)
        self.now+=301
        self.sign_in()
    def test_no_session(self):
        with self.assertRaises(AuthError):self.s.authenticate(None)
    def test_expired_session(self):
        token,_=self.sign_in();self.now+=1201
        with self.assertRaisesRegex(AuthError,'expired'):self.s.authenticate(token)
    def test_logout(self):
        token,_=self.sign_in();self.s.logout(token)
        with self.assertRaises(AuthError):self.s.authenticate(token)
    def test_unique_sessions(self):
        a,_=self.sign_in();b,_=self.sign_in();self.assertNotEqual(a,b)
    def test_username_recovery_known(self):
        self.assertEqual(self.s.recover_username('alex.viewer@example.test')['demo_delivery'],['alex.viewer'])
    def test_username_recovery_unknown_message_same(self):
        self.assertEqual(self.s.recover_username('nobody@example.test')['message'],self.s.recover_username('alex.viewer@example.test')['message'])
    def test_reset_missing_token(self):
        with self.assertRaises(AuthError):self.s.reset_password('invalid','NewPass!2027')
    def test_reset_expiration(self):
        t=self.reset_token();self.now+=601
        with self.assertRaisesRegex(AuthError,'expired'):self.s.reset_password(t,'NewPass!2027')
    def test_reset_requires_strong_password(self):
        t=self.reset_token()
        with self.assertRaises(ValueError):self.s.reset_password(t,'weak')
    def test_reset_no_reuse(self):
        t=self.reset_token()
        with self.assertRaisesRegex(ValueError,'reuse'):self.s.reset_password(t,DEMO_PASSWORD)
    def test_reset_one_time(self):
        t=self.reset_token();self.s.reset_password(t,'NewPass!2027')
        with self.assertRaises(AuthError):self.s.reset_password(t,'OtherPass!2028')
        self.sign_in(pwd='NewPass!2027')
    def test_reset_revokes_sessions(self):
        token,_=self.sign_in();self.s.reset_password(self.reset_token(),'NewPass!2027')
        with self.assertRaises(AuthError):self.s.authenticate(token)
    def test_reset_unlocks_account(self):
        for _ in range(5):
            with self.assertRaises(AuthError):self.s.login('alex.viewer','wrong')
        self.s.reset_password(self.reset_token(),'NewPass!2027')
        self.sign_in(pwd='NewPass!2027')
    def test_mfa_enrollment(self):
        _,u=self.sign_in();r=self.s.enroll_mfa(u)
        self.assertEqual(len(r['demo_recovery_codes']),3)
        self.assertTrue(self.s.status(u)['mfa_enabled'])
    def test_mfa_required(self):
        _,u=self.sign_in();self.s.enroll_mfa(u)
        r=self.s.login('alex.viewer',DEMO_PASSWORD)
        self.assertTrue(r['mfa_required']);self.assertNotIn('session',r)
    def test_mfa_correct_code(self):
        _,u=self.sign_in();self.s.enroll_mfa(u)
        r=self.s.login('alex.viewer',DEMO_PASSWORD)
        result=self.s.verify_mfa(r['challenge'],r['demo_code'])
        self.assertEqual(self.s.authenticate(result['session']).username,'alex.viewer')
    def test_mfa_wrong_code(self):
        _,u=self.sign_in();self.s.enroll_mfa(u)
        r=self.s.login('alex.viewer',DEMO_PASSWORD)
        with self.assertRaises(AuthError):self.s.verify_mfa(r['challenge'],'9999999')
    def test_mfa_expiration(self):
        _,u=self.sign_in();self.s.enroll_mfa(u)
        r=self.s.login('alex.viewer',DEMO_PASSWORD);self.now+=181
        with self.assertRaisesRegex(AuthError,'expired'):self.s.verify_mfa(r['challenge'],r['demo_code'])
    def test_recovery_code_single_use(self):
        _,u=self.sign_in();codes=self.s.enroll_mfa(u)['demo_recovery_codes']
        first=self.s.login('alex.viewer',DEMO_PASSWORD)
        self.s.verify_mfa(first['challenge'],codes[0])
        second=self.s.login('alex.viewer',DEMO_PASSWORD)
        with self.assertRaises(AuthError):self.s.verify_mfa(second['challenge'],codes[0])
    def test_viewer_read(self):
        _,u=self.sign_in();self.assertEqual(len(self.s.list_projects(u)),2)
    def test_viewer_denied_write(self):
        _,u=self.sign_in()
        with self.assertRaises(AuthError) as e:self.s.add_project(u,'Some project')
        self.assertEqual(e.exception.status,403)
    def test_editor_write(self):
        _,u=self.sign_in('sam.editor');self.assertEqual(self.s.add_project(u,'New project')['id'],3)
    def test_admin_audit_users(self):
        _,u=self.sign_in('jordan.admin');self.assertEqual(len(self.s.list_users(u)),3);self.assertTrue(self.s.audit(u))
    def test_editor_denied_audit(self):
        _,u=self.sign_in('sam.editor')
        with self.assertRaises(AuthError):self.s.audit(u)
    def test_audit_omits_secrets(self):
        _,u=self.sign_in();self.s.list_projects(u)
        logs=str(self.s.audit_log)
        self.assertNotIn(DEMO_PASSWORD,logs)
        self.assertNotIn('session',logs)
    def test_project_copy(self):
        _,u=self.sign_in();p=self.s.list_projects(u);p[0]['name']='tampered'
        self.assertNotEqual(self.s.list_projects(u)[0]['name'],'tampered')

if __name__=='__main__':unittest.main()

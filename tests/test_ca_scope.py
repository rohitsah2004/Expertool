import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch
from expertool.local_ca import LocalCA,CAError,openssl
from expertool.ca_scope import constraints,permits_host
from expertool.intercept import ManualGuard
from expertool.egress import PolicySource

@unittest.skipUnless(shutil.which('openssl'),'existing OpenSSL required')
class ConstraintTests(unittest.TestCase):
    def policy(self,include):return {'authorized':True,'include':include,'exclude':[],'allowed_modes':['manual'],'interception':{'enabled':True}}
    def leaf(self,ca,directory,host):
        root=Path(directory);key=root/'key.pem';csr=root/'leaf.csr';leaf=root/'leaf.pem';ext=root/'ext'
        openssl(['genpkey','-algorithm','EC','-pkeyopt','ec_paramgen_curve:P-256','-out',str(key)])
        openssl(['req','-new','-key',str(key),'-subj','/CN='+host,'-out',str(csr)])
        ext.write_text('subjectAltName=DNS:'+host+'\n')
        # Deliberately bypass the application guard in this local certificate
        # fixture to prove the CA extension itself rejects an outside leaf.
        openssl(['x509','-req','-in',str(csr),'-CA',str(ca.cert),'-CAkey',str(ca.key),'-set_serial','4','-days','1','-extfile',str(ext),'-out',str(leaf)])
        return subprocess.run([shutil.which('openssl'),'verify','-CAfile',str(ca.cert),str(leaf)],capture_output=True).returncode
    def test_openssl_exact_wildcard_and_outside_constraints(self):
        for include,good,bad in [(['app.example.test'],'app.example.test','sub.app.example.test'),(['*.example.test'],'sub.example.test','example.test')]:
            with self.subTest(include=include),tempfile.TemporaryDirectory() as directory:
                root=Path(directory);ca=LocalCA.for_program(root,'fixture');ca.create(program='fixture',policy=self.policy(include))
                self.assertEqual(self.leaf(ca,directory,good),0)
                self.assertNotEqual(self.leaf(ca,directory,bad),0)
                self.assertNotEqual(self.leaf(ca,directory,'outside.invalid'),0)
    def test_per_program_scope_binding_and_rotation(self):
        with tempfile.TemporaryDirectory() as directory:
            policy=self.policy(['one.example.test']);ca=LocalCA.for_program(directory,'one');other=LocalCA.for_program(directory,'two')
            self.assertNotEqual(ca.directory,other.directory);ca.create(program='one',policy=policy)
            old=ca.cert.read_bytes();policy=self.policy(['two.example.test'])
            with self.assertRaises(CAError):ca.enforce('one',policy)
            result=ca.rotate(program='one',policy=policy);self.assertTrue(result['rotated']);self.assertNotEqual(old,ca.cert.read_bytes());ca.enforce('one',policy)
            self.assertIn('Remove old CA trust',result['warning'])
            with ca.lease():
                with self.assertRaises(CAError):ca.rotate(program='one',policy=policy)
    def test_encrypted_private_key_env_only_and_missing_passphrase_refused(self):
        with tempfile.TemporaryDirectory() as directory,patch.dict(os.environ,{'EXPERTOOL_TEST_CA_PASSPHRASE':'synthetic-passphrase-2026'}):
            policy=self.policy(['127.0.0.1']);ca=LocalCA.for_program(directory,'fixture');ca.create(program='fixture',policy=policy,passphrase_env='EXPERTOOL_TEST_CA_PASSPHRASE')
            self.assertIn('ENCRYPTED PRIVATE KEY',ca.key.read_text())
            self.assertNotIn('synthetic-passphrase-2026',(ca.directory/'scope.json').read_text())
            guard=ManualGuard(PolicySource({**policy,'scan':{'ports':[443],'allow_private':True}}),'intercept');permit=guard.authorize('https://127.0.0.1/')
            ca.server_context(permit,guard)
            with patch.dict(os.environ,{'EXPERTOOL_TEST_CA_PASSPHRASE':''}):
                with self.assertRaises(CAError):ca.server_context(permit,guard)
    def test_unrepresentable_scope_and_narrow_asset_scope(self):
        with self.assertRaises(ValueError):constraints(self.policy(['example.test','app.example.test']))
        policy=self.policy(['*.example.test']);policy['asset_scope']={'include':['https://app.example.test/api/*'],'exclude':[]}
        value=constraints(policy)
        self.assertTrue(permits_host(value,'app.example.test'));self.assertFalse(permits_host(value,'other.example.test'))

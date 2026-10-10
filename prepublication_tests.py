#!/usr/bin/env python3
"""Deterministic API regressions. Run audit.py for the larger mathematics battery."""
import unittest, random, subprocess, sys, json, hashlib
from pathlib import Path
import experimental_aes512_8x8_mds as c

ZERO='bf073ec1c325616543acc765669c100cf98bd32c2e25e5e20d9b144e8186f68f655efe54969e952b3a16f95e7e29efdd73a6221b14b5fdd67f988a45b73a373a'
class Regression(unittest.TestCase):
 def test_published_vectors_and_hash(self):
  data=json.loads(Path(c.__file__).with_name('test_vectors.json').read_text())
  self.assertEqual(data['source_sha256'],hashlib.sha256(Path(c.__file__).read_bytes()).hexdigest())
  self.assertEqual(data['version'],c.VERSION)
  for v in data['vectors']:
   p,k,z=(bytes.fromhex(v[x]) for x in ['plaintext','key','ciphertext'])
   self.assertEqual(c.encrypt_block(p,k),z)
   self.assertEqual(c.decrypt_block(z,k),p)
 def test_zero_vector(self):
  self.assertEqual(c.encrypt_block(bytes(64),bytes(64)).hex(),ZERO)
  self.assertEqual(c.decrypt_block(bytes.fromhex(ZERO),bytes(64)),bytes(64))
 def test_input_lengths(self):
  for f in [c.encrypt_block,c.decrypt_block]:
   for length in [0,1,7,63,65,66,128,1024]:
    for arg in ['block','key']:
     with self.subTest(function=f.__name__,length=length,arg=arg):
      with self.assertRaises(ValueError):f(bytes(length) if arg=='block' else bytes(64),bytes(length) if arg=='key' else bytes(64))
 def test_types(self):
  for f in [c.encrypt_block,c.decrypt_block]:
   for bad in [None,64,'a'*64,[0]*64,tuple([0]*64),True]:
    with self.assertRaises(TypeError):f(bad,bytes(64))
    with self.assertRaises(TypeError):f(bytes(64),bad)
 def test_buffers_and_nonmutation(self):
  block=bytearray(range(64));key=bytearray(range(64));orig=(bytes(block),bytes(key));expected=c.encrypt_block(*orig)
  for wrap in [bytes,bytearray,memoryview]:
   self.assertEqual(c.encrypt_block(wrap(block),wrap(key)),expected)
   self.assertEqual(c.decrypt_block(wrap(expected),wrap(key)),bytes(block))
  self.assertEqual((bytes(block),bytes(key)),orig)
  # A strided memoryview is snapshotted by logical byte order.
  self.assertEqual(c.encrypt_block(memoryview(bytes(128))[::2],bytes(64)).hex(),ZERO)
 def test_structured_roundtrips(self):
  inputs=[bytes(64),bytes([255])*64,bytes(range(64)),bytes([0x55])*64,bytes([0xaa])*64]
  for p in inputs:
   for k in inputs:self.assertEqual(c.decrypt_block(c.encrypt_block(p,k),k),p)
 def test_decrypt_arbitrary_ciphertext(self):
  rng=random.Random(20261010)
  for _ in range(32):
   ct=rng.randbytes(64);key=rng.randbytes(64)
   self.assertEqual(c.encrypt_block(c.decrypt_block(ct,key),key),ct)
 def test_round_numbers(self):
  for r in [-1,31,65536]:
   with self.assertRaises(ValueError):c.round_key(bytes(64),r)
  for r in [True,1.0,'1',None]:
   with self.assertRaises(TypeError):c.round_key(bytes(64),r)
  for r in range(31):self.assertEqual(len(c.round_key(bytes(64),r)),64)
  with self.assertRaises(ValueError):c.round_key(b'',0)
 def test_negative_exponent(self):
  with self.assertRaises(ValueError):c.gf_pow(2,-1)
 def test_cli_secret_defaults(self):
  path=Path(c.__file__)
  def run(*args):return subprocess.run([sys.executable,str(path),*args],text=True,capture_output=True)
  result=run('Hello');self.assertEqual(result.returncode,0)
  self.assertNotIn('Random 512-bit demo key:',result.stdout)
  self.assertNotIn('ROUND 0:',result.stdout)
  for flag in ['--trace','--steps']:self.assertEqual(run(flag).returncode,2)
  self.assertIn('Random 512-bit demo key:',run('--show-key').stdout)
  self.assertIn('ROUND 0:',run('--trace','--show-key').stdout)
  self.assertEqual(run('--steps','--show-key').returncode,0)
  self.assertEqual(run('--avalanche','--bit','-1').returncode,2)
  self.assertEqual(run('--avalanche','--bit','512').returncode,2)
if __name__=='__main__':unittest.main(verbosity=2)

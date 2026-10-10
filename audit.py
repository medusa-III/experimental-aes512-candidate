import sys, pathlib, hashlib, json, itertools, random, time, subprocess
import numpy as np
ROOT=pathlib.Path(__file__).parent
sys.path.insert(0,str(ROOT))
import experimental_aes512_8x8_mds as c
start=time.time(); out={}; rng=random.Random(20261010)
def rb(n): return rng.randbytes(n)
def gm(a,b):
 p=0
 while b:
  if b&1:p^=a
  b>>=1;a<<=1
  if a&256:a^=0x11b
 return p
table=np.array([[gm(a,b) for b in range(256)] for a in range(256)],dtype=np.uint8)
out['field_multiplications']=sum(c.mul(a,b)==int(table[a,b]) for a in range(256) for b in range(256))
inv=[0]*256
for a in range(1,256):inv[a]=next(b for b in range(1,256) if table[a,b]==1)
out['field_inverses']=sum(c.gf_inv(a)==inv[a] for a in range(1,256))
# Derive AES S-box independently from inversion plus affine map.
sb=[]
for a in range(256):
 v=inv[a]; z=v^0x63
 for k in range(1,5):z^=((v<<k)|(v>>(8-k)))&255
 sb.append(z)
assert sb==c.SBOX
S=np.array(sb,dtype=np.uint8); IS=np.argsort(S).astype(np.uint8)
M=np.array([[inv[x^y] for y in range(8,16)] for x in range(8)],dtype=np.uint8)
assert M.tolist()==c.MIX_MATRIX
# Independent finite-field elimination.
def rank(A):
 A=[list(map(int,r)) for r in A]; r=0
 for j in range(len(A[0])):
  pivot=next((i for i in range(r,len(A)) if A[i][j]),None)
  if pivot is None:continue
  A[r],A[pivot]=A[pivot],A[r]; f=inv[A[r][j]];A[r]=[gm(x,f) for x in A[r]]
  for i in range(len(A)):
   if i!=r:
    f=A[i][j];A[i]=[x^gm(f,y) for x,y in zip(A[i],A[r])]
  r+=1
  if r==len(A):break
 return r
minors=singular=0
for k in range(1,9):
 for rows in itertools.combinations(range(8),k):
  for cols in itertools.combinations(range(8),k):
   minors+=1;singular+=rank(M[np.ix_(rows,cols)])!=k
out['MDS']={'minors':minors,'singular':singular,'branch_number':9 if singular==0 else None}
A=np.concatenate([M,np.eye(8,dtype=np.uint8)],axis=1).tolist()
for j in range(8):
 p=next(i for i in range(j,8) if A[i][j]);A[j],A[p]=A[p],A[j]
 f=inv[A[j][j]];A[j]=[gm(x,f) for x in A[j]]
 for i in range(8):
  if i!=j:
   f=A[i][j];A[i]=[x^gm(f,y) for x,y in zip(A[i],A[j])]
MI=np.array([r[8:] for r in A],dtype=np.uint8)
perm=np.array([8*((col+c.SHIFT_OFFSETS[row])%8)+row for col in range(8) for row in range(8)])
assert sorted(perm)==list(range(64)); iperm=np.argsort(perm)
def linear(states,matrix):
 v=states.reshape(-1,8,8); z=np.zeros_like(v)
 for i in range(8):
  for j in range(8):z[:,:,i]^=table[matrix[i,j],v[:,:,j]]
 return z.reshape(-1,64)
def keys(key):return np.array([list(hashlib.shake_256(b'EXPERIMENTAL-AES512-ROUNDKEY-8x8-v1'+key+r.to_bytes(2,'big')).digest(64)) for r in range(31)],dtype=np.uint8)
def enc(states,key,rounds=30):
 v=np.array(states,dtype=np.uint8).reshape(-1,64).copy();ks=keys(key);v^=ks[0]
 for r in range(1,rounds+1):
  v=S[v][:,perm]
  if r!=30:v=linear(v,M)
  v^=ks[r]
 return v
def dec(states,key):
 v=np.array(states,dtype=np.uint8).reshape(-1,64).copy();ks=keys(key)
 for r in range(30,0,-1):
  v^=ks[r]
  if r!=30:v=linear(v,MI)
  v=IS[v[:,iperm]]
 return v^ks[0]
def arr(b):return np.frombuffer(b,dtype=np.uint8)
source=ROOT/'experimental_aes512_8x8_mds.py'
out['source_sha256']=hashlib.sha256(source.read_bytes()).hexdigest()
zero=c.encrypt_block(bytes(64),bytes(64));out['zero_vector']=zero.hex()
out['document_vectors']={f:zero.hex() in (source.parent/f).read_text() for f in ['TEST_VECTORS.md','PREPUBLICATION_REPORT.md']}
count=256
for i in range(count):
 p=rb(64);k=rb(64);z=c.encrypt_block(p,k);ref=enc(arr(p),k)
 assert z==ref.tobytes();assert dec(arr(z),k).tobytes()==p;assert c.decrypt_block(z,k)==p
 assert c.round_key(k,i%31)==keys(k)[i%31].tolist()
out['independent_reference_and_roundtrips']=count
# Component inversion and round trip at scale.
fixed_key=rb(64);k=fixed_key;pts=np.array([list(rb(64)) for _ in range(4096)],dtype=np.uint8);cts=enc(pts,k)
assert np.array_equal(dec(cts,k),pts)
assert np.array_equal(linear(linear(pts,M),MI),pts)
assert np.array_equal(pts[:,perm][:,iperm],pts)
out['batch_roundtrips']=len(pts);out['ciphertext_unique']=len(set(map(bytes,cts)))
# S-box exhaustive differential and linear properties.
ddt=np.zeros((256,256),dtype=int)
for d in range(256):
 for x in range(256):ddt[d,sb[x]^sb[x^d]]+=1
par=np.array([x.bit_count()%2 for x in range(256)])
walsh=np.empty((256,256),dtype=int)
for a in range(256):
 for b in range(256):walsh[a,b]=sum(1-2*int(par[a&x]^par[b&sb[x]]) for x in range(256))
out['sbox']={'permutation':len(set(sb))==256,'differential_uniformity':int(ddt[1:].max()),'max_nontrivial_walsh':int(np.abs(walsh[1:,1:]).max())}
# Exhaustive bit positions for 8 independent baselines. Statistics are samples, not proofs.
def stats(diff):
 bits=np.unpackbits(diff,axis=1);hd=bits.sum(axis=1);corr=np.corrcoef(bits,rowvar=False);np.fill_diagonal(corr,0)
 return {'samples':len(diff),'mean_changed_bits':float(hd.mean()),'std':float(hd.std()),'min':int(hd.min()),'max':int(hd.max()),'max_output_bit_bias':float(np.max(np.abs(bits.mean(axis=0)-.5))),'max_pair_correlation':float(np.max(np.abs(corr)))}
diffs=[];kdiffs=[];rkdiffs=[]
for baseline in range(8):
 p=rb(64);k=rb(64);base=enc(arr(p),k)[0];variants=np.tile(arr(p),(512,1))
 for bit in range(512):variants[bit,bit//8]^=1<<(bit%8)
 diffs.append(enc(variants,k)^base)
 for bit in range(512):
  kk=bytearray(k);kk[bit//8]^=1<<(bit%8)
  kdiffs.append(enc(arr(p),bytes(kk))[0]^base)
  rkdiffs.append(keys(bytes(kk))^keys(k))
out['plaintext_avalanche']=stats(np.concatenate(diffs));out['key_avalanche']=stats(np.array(kdiffs))
rkbits=np.unpackbits(np.array(rkdiffs),axis=2).sum(axis=2);out['round_key_avalanche']={'samples':int(rkbits.size),'mean':float(rkbits.mean()),'min':int(rkbits.min()),'max':int(rkbits.max())}
out['balance']={'samples':len(cts),'mean_one_fraction':float(np.unpackbits(cts).mean()),'max_bit_bias':float(np.max(np.abs(np.unpackbits(cts,axis=1).mean(axis=0)-.5)))}
out['differentials']=[]
for pos in [0,7,31,63]:
 q=pts.copy();q[:,pos]^=1;d=cts^enc(q,fixed_key);out['differentials'].append({'byte':pos,'samples':len(d),'unique_differences':len(set(map(bytes,d))),'mean_hd':float(np.unpackbits(d,axis=1).sum(axis=1).mean())})
out['integrals']={}
for rounds in range(1,7):
 results=[]
 for pos in [0,7,31,63]:
  p=np.tile(arr(rb(64)),(256,1));p[:,pos]=np.arange(256);z=np.bitwise_xor.reduce(enc(p,rb(64),rounds),axis=0);results.append(int(np.unpackbits(z).sum()))
 out['integrals'][str(rounds)]=results
# invalid API inputs: exact behavior, without editing candidate.
out['input_validation']=[]
for length in [0,1,63,64,65,128]:
 for what in ['block','key']:
  try:
   z=c.encrypt_block(bytes(length) if what=='block' else bytes(64),bytes(length) if what=='key' else bytes(64)); result='accepted:'+str(len(z))
  except Exception as e:result=type(e).__name__+':'+str(e)
  out['input_validation'].append({'argument':what,'length':length,'result':result})
out['truncation_collision']=False
try:
 c.encrypt_block(bytes(64)+b'A',bytes(64));raise AssertionError('overlong block accepted')
except ValueError:pass
# CLI checks (stdout captured: random demo keys are not exposed).
out['cli']=[]
for args,expected in [([],0),(['--avalanche','--bit','511'],0),(['--avalanche','--bit','512'],2),(['a'*64],2),(['ä'*32],2)]:
 run=subprocess.run([sys.executable,str(source),*args],capture_output=True);out['cli'].append({'args':args,'returncode':run.returncode,'expected':expected});assert run.returncode==expected
out['elapsed_seconds']=time.time()-start
(ROOT/'results.json').write_text(json.dumps(out,indent=2));print(json.dumps(out,indent=2))

import importlib.util, pathlib, random, hashlib
import experimental_aes512_8x8_mds as new
p=pathlib.Path(__file__).parent/'compatibility/v01.py'
assert hashlib.sha256(p.read_bytes()).hexdigest()=='f50c3958064f5bd9addf588ca49b9457847c5621b9f9c7bcd0908cf976f1cf76'
spec=importlib.util.spec_from_file_location('old',p);old=importlib.util.module_from_spec(spec);spec.loader.exec_module(old)
rng=random.Random(20261010)
for _ in range(64):
 block=rng.randbytes(64);key=rng.randbytes(64)
 assert old.encrypt_block(block,key)==new.encrypt_block(block,key)
print('64/64 valid-input compatibility comparisons passed')

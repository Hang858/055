#!/usr/bin/env python3
"""Executable acceptance for the configurable certificate tool."""
import copy,json,os,subprocess,tempfile,unittest
from pathlib import Path
BINARY=Path(os.environ.get("CERTTOOL_BINARY", str(Path(__file__).resolve().parents[1]/".build/certtool/pqc-certtool")))
class CertToolTests(unittest.TestCase):
 def setUp(self):
  self.assertTrue(BINARY.is_file(), "Configurable certificate executable has not been implemented")
  self.tmp=tempfile.TemporaryDirectory(prefix="certtool-test-"); self.addCleanup(self.tmp.cleanup); self.work=Path(self.tmp.name)
 def config(self,mode="pure-pq",algo="ML-DSA-44"):
  return {"schema_version":1,"mode":mode,"output_dir":"output","root":{"name":"root","common_name":"Factory Root","algorithm":"SM2" if mode=="sm2" else algo,"valid_days":3650},"intermediates":[{"name":"inter","common_name":"Factory Intermediate","algorithm":"SM2" if mode=="sm2" else algo,"valid_days":1825}],"leaves":[{"name":"user","common_name":"Factory User","algorithm":"SM2" if mode=="sm2" else "ML-KEM-512","valid_days":365}]}
 def call(self,*args,ok=True):
  p=subprocess.run([str(BINARY),*map(str,args)],cwd="/",capture_output=True,text=True,timeout=120)
  self.assertEqual(p.returncode==0,ok,p.stdout+p.stderr);return p
 def save(self,c,extra=""):
  path=self.work/"config.json";path.write_text(json.dumps(c)+extra);return path
 def test_version_and_algorithms(self):
  self.assertIn("pqc-certtool",self.call("version").stdout)
  a=json.loads(self.call("algorithms").stdout); self.assertIn("ML-DSA-87",a["signature"]);self.assertIn("SLH-DSA-SHA2-256s",a["signature"]);self.assertIn("ML-KEM-1024",a["kem"])
 def test_custom_chain_all_modes(self):
  for mode in ["pure-pq","sm2-hybrid","rsa-hybrid","sm2"]:
   with self.subTest(mode=mode):
    c=self.config(mode);c["output_dir"]=mode;path=self.save(c)
    self.call("check","-config",path);self.call("generate","-config",path);self.call("verify","-config",path)
    out=self.work/mode;self.assertTrue((out/"root.crt").exists());self.assertTrue((out/"user.crt").exists());self.assertTrue((out/"user.pub").exists());self.assertEqual(out.stat().st_mode&0o777,0o700)
    for key in out.glob("*.key"):self.assertEqual(key.stat().st_mode&0o777,0o600)
    before=(out/"user.crt").read_bytes();self.call("generate","-config",path,ok=False);self.assertEqual((out/"user.crt").read_bytes(),before)
    c["leaves"][0]["common_name"]="Wrong identity";self.call("verify","-config",self.save(c),ok=False)
 def test_signature_parameters(self):
  for i,algo in enumerate(["ML-DSA-44","ML-DSA-65","ML-DSA-87","SLH-DSA-SHA2-128s","SLH-DSA-SHA2-128f","SLH-DSA-SHA2-192s","SLH-DSA-SHA2-192f","SLH-DSA-SHA2-256s","SLH-DSA-SHA2-256f"]):
   with self.subTest(algo=algo):
    c=self.config(algo=algo);c["intermediates"]=[];c["leaves"][0]["algorithm"]=algo;c["output_dir"]=f"sig-{i}";path=self.save(c);self.call("generate","-config",path);self.call("verify","-config",path)
 def test_all_kem_parameters(self):
  c=self.config();c["leaves"]=[dict(c["leaves"][0],name=f"user{i}",algorithm=a) for i,a in enumerate(["ML-KEM-512","ML-KEM-768","ML-KEM-1024"])];path=self.save(c);self.call("generate","-config",path);self.call("verify","-config",path)
 def test_invalid_configs(self):
  base=self.config()
  variants=[]
  for key,value in [("mode","unknown"),("schema_version",2),("extra",True),("output_dir","")]:
   c=copy.deepcopy(base);c[key]=value;variants.append(c)
  for key,value in [("name","../escape"),("algorithm","ML-KEM-512"),("valid_days",0)]:
   c=copy.deepcopy(base);c["root"][key]=value;variants.append(c)
  c=copy.deepcopy(base);c["leaves"][0]["valid_days"]=5000;variants.append(c)
  c=copy.deepcopy(base);c["leaves"][0]["name"]="root";variants.append(c)
  c=copy.deepcopy(base);c["leaves"][0]["algorithm"]="unknown-signature";variants.append(c)
  for c in variants:self.call("check","-config",self.save(c),ok=False)
  self.call("check","-config",self.save(base," {}"),ok=False)
  self.assertFalse((self.work/"output").exists())
 def test_import_public_key_without_private_key(self):
  for mode,algo in [("pure-pq","ML-DSA-44"),("sm2","SM2")]:
   c=self.config(mode);c["leaves"][0]["algorithm"]=algo;c["output_dir"]="original-"+mode;path=self.save(c);self.call("generate","-config",path)
   c["leaves"][0]["public_key_file"]="original-"+mode+"/user.pub";c["output_dir"]="imported-"+mode;path=self.save(c);self.call("generate","-config",path);self.call("verify","-config",path)
   self.assertFalse((self.work/c["output_dir"]/"user.key").exists());self.assertEqual((self.work/c["output_dir"]/"user.pub").read_bytes(),(self.work/("original-"+mode)/"user.pub").read_bytes())
 def test_invalid_import_is_rejected(self):
  c=self.config();c["leaves"][0]["public_key_file"]="bad.pub";(self.work/"bad.pub").write_bytes(b"not a key");path=self.save(c);self.call("check","-config",path,ok=False);self.call("generate","-config",path,ok=False);self.assertFalse((self.work/"output").exists())
 def test_tampered_and_missing_certificate(self):
  c=self.config();path=self.save(c);self.call("generate","-config",path);cert=self.work/"output/user.crt";original=cert.read_bytes();cert.write_bytes(original.replace(b"CERTIFICATE",b"BAD",1));self.call("verify","-config",path,ok=False);cert.write_bytes(original);(self.work/"output/root.crt").unlink();self.call("verify","-config",path,ok=False)
if __name__=="__main__":unittest.main(verbosity=2)

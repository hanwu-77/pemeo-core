"""Synthetic software authenticator. Real signatures, NOT human/physical proof."""
import hashlib,json,secrets
import cbor2
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from ecom_backend.webauthn_adapter import encode,decode


class SoftwareAuthenticator:
    def __init__(self,*,backup=False):
        self.key=ec.generate_private_key(ec.SECP256R1())
        self.identifier=secrets.token_bytes(32)
        self.count=0;self.backup=backup;self.handle=None

    def response(self,options,*,register=False,origin='https://localhost:8443',rp='localhost',uv=True,up=True,cross=False,backed_up=False,count=None,handle=None):
        client={'type':'webauthn.create' if register else 'webauthn.get','challenge':options['challenge'],'origin':origin,'crossOrigin':cross}
        client_bytes=json.dumps(client,separators=(',',':')).encode()
        flags=(1 if up else 0)|(4 if uv else 0)|(8 if self.backup else 0)|(16 if backed_up else 0)
        self.count=self.count+1 if count is None else count
        auth=hashlib.sha256(rp.encode()).digest()+bytes([flags|(64 if register else 0)])+self.count.to_bytes(4,'big')
        response={'clientDataJSON':encode(client_bytes)}
        if register:
            self.handle=options['user']['id']
            public=self.key.public_key().public_numbers()
            cose={1:2,3:-7,-1:1,-2:public.x.to_bytes(32,'big'),-3:public.y.to_bytes(32,'big')}
            auth+=bytes(16)+len(self.identifier).to_bytes(2,'big')+self.identifier+cbor2.dumps(cose)
            response['attestationObject']=encode(cbor2.dumps({'fmt':'none','attStmt':{},'authData':auth}))
        else:
            response.update(authenticatorData=encode(auth),signature=encode(self.key.sign(auth+hashlib.sha256(client_bytes).digest(),ec.ECDSA(hashes.SHA256()))),userHandle=handle if handle is not None else self.handle)
        return json.dumps({'id':encode(self.identifier),'rawId':encode(self.identifier),'type':'public-key','response':response}).encode()

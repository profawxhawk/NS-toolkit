import asn1
import binascii
from pyasn1.codec.der import decoder
from rsa.asn1 import AsnPubKey
from base64 import b64decode
        
with open('./Pubkey_DA/PKDApri.private', 'rb') as privatefile:
                DApriv=privatefile.read()
with open('.ssh/id_rsa') as key_file:
    b64_serialisation = ''.join(key_file.readlines()[1:-1])
    
value = decoder.decode(b64decode(DApriv), asn1Spec=AsnPubKey())

print(value)

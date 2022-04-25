import random
import sys
import codecs
import pickle
import hmac
import hashlib 
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import ast
import math
#Elgamal Works

#bob
key1 = ''
with open('./priv_key.txt','rb') as priv:
    key1 = priv.read()

key2=''
with open('./pub_key.txt') as pub:
    key2 = pub.read()

priv_key = RSA.importKey(key1)
pub_key = RSA.importKey(key2)

encryptor = PKCS1_OAEP.new(pub_key)
encrypted =  encryptor.encrypt(b'1@eedfbd')

decryptor = PKCS1_OAEP.new(priv_key)
decrypted = decryptor.decrypt(ast.literal_eval(str(encrypted)))
print(decrypted)
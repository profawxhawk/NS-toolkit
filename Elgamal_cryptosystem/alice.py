import socket
import pickle
import random
import time
import hashlib
import hmac
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import ast
import math

send_s = socket.socket()
recv_s = socket.socket()

print("Socket created")
port1 = 34564
port2 = port1+1


send_s.bind(('',port1))
send_s.listen(5)
bob,addr = send_s.accept()
bob.send(b'Im Alice')

recv_s.connect(('127.0.0.1',port2))
x = str(recv_s.recv(1024))
print(x)
print("bob to alice established")
#-----------Encryption--------------
hmac_secret = b'1@eedfbd'
key2=''
with open('./pub_key.txt') as pub:
    key2 = pub.read()
#get Bob's Public Key
pub_key = RSA.importKey(key2)
encryptor = PKCS1_OAEP.new(pub_key)
encrypted =  encryptor.encrypt(hmac_secret)
encrypted_secret_dict = {'secret' : encrypted}
#send encrypted hmac secret to bob
bob.send(pickle.dumps(encrypted_secret_dict))
# receive {p,alpha(b),beta(g^b)} from bob
pubkey = pickle.loads(recv_s.recv(4096))
#-----------verify hmac----------------------
received_hmac = pubkey['hmac']
del pubkey['hmac']
hmac_obj1 = hmac.new(hmac_secret,pickle.dumps(pubkey),hashlib.sha512)
if received_hmac==hmac_obj1.hexdigest():
    print("Hmac verified")
#---------------Use public key--------------------
p = pubkey['p']
alpha = pubkey['alpha']
beta = pubkey['beta']
mess = "hello1 hello2 hello3 oh ansdsd !!! sddsdp oj ddnsldknn dskdsdsfj"
dict2 = {"length":len(mess)}
#send length of message
bob.send(pickle.dumps(dict2))
for it in range(len(mess)):
    #calculate g^a and g^ab and send message
    m = mess[it]
    k = random.randint(2,p-1)#b
    r = pow(alpha,k,p)#g^a
    val = hex(ord(m))
    M = (int(val,16))
    t = (pow(beta,k) * M)%p#m*g^ab
    temp_dict = {'c1':r,'c2':t}
    #append hmac
    hmac_obj1.update(pickle.dumps(temp_dict))
    temp_dict['hmac']=hmac_obj1.hexdigest()
    print(m)
    #send c1 and c2
    bob.send(pickle.dumps(temp_dict))
    time.sleep(0.5)

recv_s.close()
bob.close()
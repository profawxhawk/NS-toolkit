import socket
import random
import math
import pickle
import hmac
import hashlib

recv_s=socket.socket()
send_s = socket.socket()
port1 = 34564
port2=port1+1

recv_s.connect(('127.0.0.1',port1))
x = str(recv_s.recv(1024))
print(x)
print("Alice to bob established")

send_s.bind(('',port2))
send_s.listen(5)
alice,addr = send_s.accept()
alice.send(b'Im bob')
#---------Encryption starts here------------
p = 797
alpha=2
z = random.randint(2,p-1)
beta = pow(alpha,z,p)
print(beta)
#send public key {p,alpha,beta}
m = {"p":p,"alpha":alpha,"beta":beta}
#create hashmac object
hmac_obj = hmac.new(b'1@#4%^&qwc(',pickle.dumps(m),hashlib.sha512)
m['hmac'] = hmac_obj.hexdigest()
final_str=""
alice.send(pickle.dumps(m))
#receive message length
dict2 = pickle.loads(recv_s.recv(4096))
for i in range(dict2['length']):
    neg_z = p-1-z
    #receive c1,c2
    temp_dict = pickle.loads(recv_s.recv(4096))
    #verify hmac
    received_hmac = temp_dict['hmac']
    del temp_dict['hmac']
    hmac_obj.update(pickle.dumps(temp_dict))
    if received_hmac==hmac_obj.hexdigest():
        print("Hmac Verified")
    r = temp_dict['c1']
    t = temp_dict['c2']
    #decryption
    recv_m = (t*pow(r,neg_z))%p
    hex_str = (hex(recv_m))
    hex_str = hex_str[2::]#remove 0x
    recv_message = bytes.fromhex(hex_str).decode('utf-8')
    #add received message to final string
    final_str = final_str+recv_message
    print(recv_message)

print(final_str)
alice.close()
recv_s.close()
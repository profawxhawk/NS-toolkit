import random
import sys
import codecs
import pickle
import hmac
import hashlib 
#Elgamal Works

#bob
p = 797
alpha=2
z = random.randint(2,p-1)
beta = pow(alpha,z,p)#g^a
dict1 = {"p":p,"alpha":alpha,"beta":beta}
q = pickle.dumps(dict1)
print(q)



#alice
mess="abcdefghijklmnopqrstuvwxyz?!@#$%^&() "
final_str=""
for it in range(len(mess)):
    m = mess[it]
    print(m)
    k = random.randint(2,p-1)#b
    r = pow(alpha,k,p)#g^b
    val = hex(ord(m))
    print("hex :"+val)
    M = (int(val,16))
    print(M)
    t = (pow(beta,k) * M)%p#m*g^ab
    #bob
    neg_z = p-1-z
    recv_m = (t*pow(r,neg_z))%p
    print(recv_m)
    hex_str = (hex(recv_m))
    print(hex_str)
    hex_str = hex_str[2::]#remove 0x
    print(hex_str)
    recv_message = bytes.fromhex(hex_str).decode('utf-8')
    final_str = final_str+recv_message

print(final_str)

#HMAC Testing
secret_dict = {"hi":"sdsd","qw":234}
obj = hmac.new(b'secret_key',pickle.dumps(secret_dict),hashlib.sha512)
secret_dict['hmac']=obj.hexdigest()
#send secret dict
received_dict = secret_dict
received_hmac = received_dict['hmac']
del received_dict['hmac']
obj2 = hmac.new(b'secret_key',pickle.dumps(received_dict),hashlib.sha512)
if received_hmac==obj2.hexdigest():
    print("Too good")
print(received_dict)

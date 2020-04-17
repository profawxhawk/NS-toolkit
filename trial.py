import random
import sys
import codecs
#Elgamal Works

#bob
p = 797
alpha=2
z = random.randint(2,p-1)
beta = pow(alpha,z,p)

#alice
mess="abcdefghijklmnopqrstuvwxyz?!@#$%^&()"
final_str=""
for it in range(len(mess)):
    m = mess[it]
    print(m)
    k = random.randint(2,p-1)
    r = pow(alpha,k,p)
    val = hex(ord(m))
    print("hex :"+val)
    M = (int(val,16))
    print(M)
    t = (pow(beta,k) * M)%p
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
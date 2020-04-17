import socket
import random

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
#send public key {p,alpha,beta}

alice.close()
recv_s.close()
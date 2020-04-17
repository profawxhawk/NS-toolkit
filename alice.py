import socket

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
# receive {p,alpha,beta} from bob



recv_s.close()
bob.close()
import socket
import json
import select
import threading
import binascii
import math
from Crypto.PublicKey import RSA

servers = [] 
portlist={'client1':8080,'client2':8081}
print("PKDA switching on")

for port in portlist.keys():
    print("Binding ports to "+port)
    ds = ("0.0.0.0", portlist[port])
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(ds)
    server.listen(1)
    servers.append(server)

def encrypt(value,key):
    key = RSA.importKey(key.decode('utf8'))
    print(value) 
    temp=int.from_bytes(value, byteorder='big')
    temp%=key.n 
    e=key.e
    # while(e>0):
    #     if(e&1)
    # byte_len = int(math.ceil(temp.bit_length() / 8))
    # x_bytes = temp.to_bytes(byte_len, byteorder='big')
    # print(x_bytes)
    return value

def serve(conn):
    while True:
        data = conn.recv(1024).decode('utf-8')
        if not data:
            break
        data=json.loads(data)

        if ('receiver' or 'time') not in data.keys():
            conn.send("0".encode('utf8'))
            break

        if data['receiver'] in portlist.keys():
            DApriv=''
            clientpub=''
            with open('./Pubkey_DA/PKDApri.private', 'rb') as privatefile:
                DApriv=privatefile.read()
            with open('./Pubkey_clients/'+data['receiver']+'pub.public', 'rb') as publicfile:
                clientpub=publicfile.read()

            data.update({'public_key':clientpub.decode('utf8')})
            conn.send(encrypt(json.dumps(data).encode('utf8'),DApriv))
        
        else:
            conn.send("client not found".encode('utf-8'))

    conn.close()

while True:
    print("waiting for client")
    readable,_,_ = select.select(servers, [], [])
    ready_server = readable[0]
    connection, address = ready_server.accept()
    t1=threading.Thread(target=serve(connection))

import socket
import json
import select
import threading
import binascii
import math
from Crypto.PublicKey import RSA
import concurrent.futures
servers = [] 
portlist={'client1':8080,'client2':8081}
print("PKDA switching on")

for port in portlist.keys():
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect(('0.0.0.0',portlist[port]))
    print("Server listening on port "+str(portlist[port]))
    servers.append(client)
    # ds = ("0.0.0.0", portlist[port])
    # server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    # server.bind(ds)
    # server.listen(1)
    # servers.append(server)

def encrypt(value,key):
    key = RSA.importKey(key.decode('utf8'))
    temp=int.from_bytes(value, byteorder='big')
    cipher = pow(temp,key.d,key.n)
    byte_len = int(math.ceil(cipher.bit_length() / 8))
    return cipher.to_bytes(byte_len,byteorder='big')

def serve(conn):
    while True:
        data = conn.recv(1024).decode('utf-8')
        if not data:
            continue
        data=json.loads(data)

        if ('receiver' or 'time') not in data.keys():
            conn.send("0".encode('utf8'))
            

        if data['receiver'] in portlist.keys():
            print(str(data['receiver'])+" public key requested")
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

def Server_init(i):
    try:
        serve(i)
    except:
        print('error with item')

# while True:
print("waiting for client")
executor = concurrent.futures.ProcessPoolExecutor(len(servers))
futures = [executor.submit(Server_init, i) for i in servers]
concurrent.futures.wait(futures)
    # readable,_,_ = select.select(servers, [], [])
    # ready_server = readable[0]
    # print(ready_server)
    # connection, address = ready_server.accept()
    # t1=threading.Thread(target=serve(connection))

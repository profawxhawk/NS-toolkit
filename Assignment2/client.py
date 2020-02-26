import socket
import json
from Crypto.PublicKey import RSA
import math


portlist={'client1':8080,'client2':8081}
portlist_clients={'client2':8082}
print("Enter your name")
name=input()
port=portlist[name]


def decrypt(value):
    with open('./Pubkey_DA/PKDApub.public', 'rb') as priv2:
        key2 = priv2.read()
    key2 = RSA.importKey(key2.decode('utf8')) 
    cipher = int.from_bytes(value, byteorder='big') 
    message = pow(cipher,key2.e,key2.n)
    print(message)
    byte_len = int(math.ceil(message.bit_length() / 8))
    print(message.to_bytes(byte_len,byteorder='big').decode('utf8'))
    return message.to_bytes(byte_len,byteorder='big').decode('utf8')


def connect_server(port):
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect(('0.0.0.0', port))
    return client

def ask_key(client,receiver):
    request={'receiver':receiver,'time':"10"}
    client.send(json.dumps(request).encode('utf8'))

    from_server = client.recv(4096)
    from_server = decrypt(from_server)
    if(from_server=="0"):
        print("Wrong format.. breaking connection")
    elif (from_server=="client not found"):
        print("Server cannot find requested client")
    elif 'public_key' in json.loads(from_server):
        data=json.loads(from_server)
        print("public key acquired!")
        client.close()
        return 1
    client.close()
    return 0


while True:
    print("a) Initiate connection to server")
    ans=input()
    while(ans=='a'):
        print("choose client (enter name)")
        for i in portlist.keys():
            if i!=name:
                print(i)
        recieve=input()

        if recieve not in portlist.keys() or recieve==name:
            print("wrong input enter again")
            continue
        print("okk??")
        client=connect_server(port)
        print("ok2")
        x = ask_key(client,recieve)
        if x==0:
            continue
        

            

        
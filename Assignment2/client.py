import socket
import json
from Crypto.PublicKey import RSA
import math
import threading
import time
portlist={'client1':8080,'client2':8081}
portlist_clients={'client1':8082,'client2':8083}
public_keys_list={}
client_socket_list={}
lock = threading.Lock()
messy=False
print("Enter your name")
name=input()
port=portlist[name]
ds = ("0.0.0.0", port)
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
client.bind(ds)
client.listen(1)
server_conn=socket.socket()
print("Client listening on port "+str(port))
latest_nonce="10"
port=portlist_clients[name]
ds = ("0.0.0.0", port)
client1 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client1.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
client1.bind(ds)
client1.listen(1)
nonce_dict={}

def gen_nonce(length):
    seq = string.ascii_uppercase+string.digits
    #print(seq)
    randu_str = ''
    for i in range(length):
        randu_str = randu_str + secrets.choice(seq)
    #print(os.NAMESPACE_DNS)
    return int(str(os.uuid5(os.NAMESPACE_DNS,randu_str).int)[:length])


print("Client listening on port "+str(port))
def decrypt(value,key2,priv):
    key2 = RSA.importKey(key2.decode('utf8')) 
    cipher = int.from_bytes(value, byteorder='big') 
    if priv:
        message = pow(cipher,key2.d,key2.n)
    else:
        message = pow(cipher,key2.e,key2.n)
    byte_len = int(math.ceil(message.bit_length() / 8))
    return message.to_bytes(byte_len,byteorder='big').decode('utf8')


def connect_server(port):
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect(('0.0.0.0', port))
    return client

def ask_key(client,receiver):
    request={'receiver':receiver,'time':"10"}
    client.send(json.dumps(request).encode('utf8'))
    from_server = client.recv(4096)
    key2=''
    with open('./Pubkey_DA/PKDApub.public', 'rb') as priv2:
        key2 = priv2.read()
    from_server = decrypt(from_server,key2,False)
    if(from_server=="0"):
        print("Wrong format.. breaking connection")
    elif (from_server=="client not found"):
        print("Server cannot find requested client")
    elif 'public_key' in json.loads(from_server):
        data=json.loads(from_server)
        print("public key acquired!")
        return (1,data)
    return (0,None)

def send_init_to_client(clientid,pub_key):
    print("Sending initial request to "+clientid)
    conn=client_socket_list[clientid]
    request={'id':name,'nonce':latest_nonce}
    request=encrypt(json.dumps(request).encode('utf8'),pub_key.encode('utf8'),False)
    conn.send(request)
    
def encrypt(value,key,priv):
    key = RSA.importKey(key.decode('utf8'))
    temp=int.from_bytes(value, byteorder='big')
    if not priv:
        cipher=pow(temp,key.e,key.n)
    else:
        cipher = pow(temp,key.d,key.n)
    byte_len = int(math.ceil(cipher.bit_length() / 8))
    return cipher.to_bytes(byte_len,byteorder='big')

def change_nonce():
    return latest_nonce

def receive_on_new_client(clientsocket,addr,conn):
    session_client=''
    while True:
        msg = clientsocket.recv(4096)
        key=''
        with open('./Pubkey_clients/'+name+'pri.private', 'rb') as priv2:
            key = priv2.read()
        msg=decrypt(msg,key,True)
        try:
            if 'id' in json.loads(msg):
                print()
                print("Message initiaition request from "+str(json.loads(msg)['id']))
                print("Acquiruing public key of "+str(json.loads(msg)['id']))
                x,data = ask_key(conn,json.loads(msg)['id'])
                public_keys_list[json.loads(msg)['id']]=data['public_key']
                request={'nonce_sender':latest_nonce,'nonce_receiver':json.loads(msg)['nonce'],'name':name}
                pub_key=data['public_key']
                session_client=json.loads(msg)['id']
                request=encrypt(json.dumps(request).encode('utf8'),pub_key.encode('utf8'),False)
                receiver=client_socket_list[session_client]
                receiver.send(request)

            elif 'nonce_receiver' in json.loads(msg) and json.loads(msg)['nonce_receiver']==latest_nonce:
                if 'nonce_sender' in json.loads(msg):
                    session_client=json.loads(msg)['name']
                    pub_key=public_keys_list[session_client]
                    receiver=client_socket_list[session_client]
                    receiver.send(encrypt(json.dumps({'nonce_receiver':json.loads(msg)['nonce_sender']}).encode('utf8'),pub_key.encode('utf8'),False))
                else:
                    receiver=client_socket_list[session_client]
                    pub_key=public_keys_list[session_client]
                    receiver.send(encrypt(json.dumps({'message':"Ready to receive"}).encode('utf8'),pub_key.encode('utf8'),False))
            
            elif 'message' in json.loads(msg):
                if json.loads(msg)['message']=="Ready to receive":
                    print("In message thread")
                    print("Secure connection to "+session_client+" established")
                    print("Type message to send")
                    lock.acquire(blocking=True, timeout=-1)
                    message=input()
                    lock.release()
                    receiver=client_socket_list[session_client]
                    pub_key=public_keys_list[session_client]
                    receiver.send(encrypt(json.dumps({'message':message}).encode('utf8'),pub_key.encode('utf8'),False))
                    print("Message sent to "+session_client+" waiting for reply")
                else:
                    print("In message thread")
                    print("Message received from "+session_client)
                    print("Message is " + json.loads(msg)['message'])
                    if(json.loads(msg)['message']=="good bye"):
                        print("Message session over press enter to go to main thread. You can chat with another client if you havnt initiated a chat before")
                        continue
                    print("In message thread")
                    print("Type message to send. If program switches to main thread please enter message again")
                    messy=True
                    lock.acquire(blocking=True, timeout=-1)
                    message=input()
                    lock.release()
                    receiver=client_socket_list[session_client]
                    pub_key=public_keys_list[session_client]
                    receiver.send(encrypt(json.dumps({'message':message}).encode('utf8'),pub_key.encode('utf8'),False))
                    if(message=="good bye"):
                        print("breaking connection... press enter to go to main thread. You can chat with another client if you havnt initiated a chat before")
                        continue
                    else:
                        print("Message sent to "+session_client+" waiting for reply")
                    
            else:
                print("Message not in right format")
                    
                    
        except:
            print('Some error ... ')
            print("message received from "+str(addr))
    clientsocket.close()

def connection_from_all_clients(conn):
    t=len(portlist_clients.keys())
    count=1
    while True:
        print("Waiting for connections")
        c1, addr = client1.accept()   
        t1=threading.Thread(target=receive_on_new_client,args=(c1,addr,conn))
        t1.start()
        count+=1
        if count==t:
            print("All connections connected")
            break

def listen_to_connections():
    for port in portlist_clients.keys():
        if port!=name:
            client2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client2.connect(('0.0.0.0',portlist_clients[port]))
            client_socket_list[port]=client2
            print("Server listening on port "+str(portlist_clients[port]))

def generate_nonces():
    for port in portlist_clients.keys():
        if port!=name:
            nonce_dict[port]=gen_nonce(8)
while True:
    print("Make sure all clients are up and running, otherwise program will crash")
    print("Please start the PKDA server now")
    print("a) Initiate connection to server")
    ans=input()
    c, addr=client.accept()
    print('Connected to PKDA server')
    print('Make sure to follow order mentioned in doc to establish proper connections between clients')
    res='a'
    while(res!='c'):
        print("In main thread")
        print("a) Listen to connections")
        print("b) accept connections")
        print("c) All connections established")
        lock.acquire(blocking=True, timeout=-1)
        if messy:
            print("This is the message thread.There is a small glitch please enter message again.")
        res=input()
        lock.release()
        if res=='a':
            listen_to_connections()
        if res=='b':
            connection_from_all_clients(c)
        elif res=='c':
            print('All conections up, moving to next stage')
    while(res=='c'):
        # generate_nonces()
        print("In main thread")
        print("choose client (enter name) for getting public key")
        for i in portlist.keys():
            if i!=name:
                print(i)
        lock.acquire(blocking=True, timeout=-1)
        recieve=input()
        lock.release()
        if recieve not in public_keys_list.keys():
            if recieve not in portlist.keys() or recieve==name:
                print("wrong input enter again")
                continue
            x,data = ask_key(c,recieve)
            public_keys_list[recieve]=data['public_key']
            if x==0:
                continue
            print("Initiating connection with "+recieve+".....")
            print()
            client_to=send_init_to_client(recieve,data['public_key'])
        else:
            print("Initiating connection with "+recieve+".....")
            print()
            client_to=send_init_to_client(recieve,public_keys_list[recieve])
        print("Wait for 100 seconds to communicate with another client")
        time.sleep(100)
    




    
        

            

        
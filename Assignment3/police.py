import socket
import json
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import base64
import math
import threading
import time
import secrets
from datetime import datetime
import string 
import uuid as os
from classes import ticket,encrypt,sign,decrypt
from datetime import datetime
import chardet
import binascii
main_server_list={'server1':8080,'server2':8081}
police_list={'police1':8001,'police2':8002}
ticket_server=8000
socket_list={}

public_keys_list={}

# lock = threading.Lock()
# messy=False
print("Enter your name")
name=input()
# port=portlist[name]
# ds = ("0.0.0.0", port)
# client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# client.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
# client.bind(ds)
# client.listen(1)
# server_conn=socket.socket()
# print("Client listening on port "+str(port))
# latest_nonce="10"
# port=portlist_clients[name]
# ds = ("0.0.0.0", port)
# client1 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# client1.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
# client1.bind(ds)
# client1.listen(1)
nonce_dict={}


def get_time():
    return (datetime.now().strftime("%m/%d/%Y,%H:%M:%S"))

def gen_nonce(length):
    seq = string.ascii_uppercase+string.digits
    #print(seq)
    randu_str = ''
    for i in range(length):
        randu_str = randu_str + secrets.choice(seq)
    #print(os.NAMESPACE_DNS)
    return int(str(os.uuid5(os.NAMESPACE_DNS,randu_str).int)[:length])




def connect_server(port):
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect(('0.0.0.0', port))
    return client

def ask_key(client,receiver):
    latest_time=get_time()
    request={'receiver':receiver,'time':latest_time}
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
    elif 'public_key' in json.loads(from_server) and json.loads(from_server)['time']==latest_time :
        data=json.loads(from_server)
        print("public key acquired!")
        return (1,data)
    else:
        print("Replay Attack")
    return (0,None)

def send_init_to_client(clientid,pub_key):
    print("Sending initial request to "+clientid)
    conn=client_socket_list[clientid]
    request={'id':name,'nonce':nonce_dict[clientid]}
    request=encrypt(json.dumps(request).encode('utf8'),pub_key.encode('utf8'),False)
    conn.send(request)
    
def receive_on_new_client(clientsocket,addr,conn):
    session_client=''
    global nonce_dict
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
                request={'nonce_sender':nonce_dict[json.loads(msg)['id']],'nonce_receiver':json.loads(msg)['nonce'],'name':name}
                pub_key=data['public_key']
                session_client=json.loads(msg)['id']
                request=encrypt(json.dumps(request).encode('utf8'),pub_key.encode('utf8'),False)
                receiver=client_socket_list[session_client]
                receiver.send(request)

            elif 'nonce_receiver' in json.loads(msg) :
                if 'nonce_sender' in json.loads(msg) and json.loads(msg)['nonce_receiver']==nonce_dict[json.loads(msg)['name']]:
                    session_client=json.loads(msg)['name']
                    pub_key=public_keys_list[session_client]
                    receiver=client_socket_list[session_client]
                    receiver.send(encrypt(json.dumps({'nonce_receiver':json.loads(msg)['nonce_sender']}).encode('utf8'),pub_key.encode('utf8'),False))
                elif json.loads(msg)['nonce_receiver']==nonce_dict[session_client]:
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


def listen_to_ticket_server():
    client2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client2.connect(('127.0.0.1',8000))
    socket_list['ticket_server']=client2


def listen_to_all_servers():
    for i in main_server_list.keys():
        client2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client2.connect(('127.0.0.1',main_server_list[i]))
        socket_list[i]=client2

def acquire_ticket1():

    conn=socket_list['ticket_server']
    with open('./police_keys/'+name+'.private', 'rb') as priv2:
        priv_key = priv2.read()
    with open('./ticket_server_keys/ticketpub.public', 'rb') as pub:
        pub_key = pub.read()
    # priv_key=RSA.importKey(priv_key)
    # pub_key=RSA.importKey(pub_key)
    request={'id':name,'message': binascii.hexlify(b'hello').decode('utf-8')}
    request=encrypt(pub_key,json.dumps(request).encode('utf8'))
    conn.send(request)
    msg = conn.recv(4096)
    tickety=decrypt(priv_key,msg).decode('utf-8')
    tickety=json.loads(tickety)
    tickety1=ticket(tickety['ID'],tickety['issue'],tickety['lifetime'])
    return tickety1

def acquire_ticket2(license,ticket1):
    conn=socket_list['ticket_server']
    with open('./police_keys/'+name+'.private', 'rb') as priv2:
        priv_key = priv2.read()
    with open('./ticket_server_keys/ticketpub.public', 'rb') as pub:
        pub_key = pub.read()

    request={'license':license,'ticket': ticket1.toJSON()}
    request=encrypt(pub_key,json.dumps(request).encode('utf8'))
    conn.send(request)
    msg = conn.recv(4096)
    tickety=decrypt(priv_key,msg).decode('utf-8')
    print(tickety)
    tickety=json.loads(tickety)
    tickety1=ticket(tickety['ID'],tickety['issue'],tickety['lifetime'],tickety['main_server'])
    return tickety1

ticket1=None
ticket2=None
while True:
    print("Make sure all servers are up and running")
    print("Please start all the servers now")
    print("Enter license number")
    license=input()
    listen_to_ticket_server()
    # listen_to_all_servers()
    print('Connected to ticket server')

    if ticket1 is None:
        ticket1=acquire_ticket1()

    if (ticket1 is not None) and (ticket1.issue+ticket1.lifetime)<datetime.now().timestamp():
        print(ticket1.issue,ticket1.lifetime,datetime.now().timestamp())
        print("Previous ticket1 expired acquiring new ticket")
        ticket1=acquire_ticket1()

    print('Ticket 1 acquired')

    if ticket1 is not None and ticket2 is None:
        ticket2=acquire_ticket2(license,ticket1)

    if  ticket1 is not None and (ticket2 is not None and ticket2.issue+ticket2.lifetime)<datetime.now().timestamp():
        print("Previous ticket2 expired acquiring new ticket")
        ticket2=acquire_ticket2(license,ticket1)


    print('Ticket 2 acquired')






    # res='a'
    # while(res!='c'):
    #     print("In main thread")
    #     print("a) Listen to connections")
    #     print("b) accept connections")
    #     print("c) All connections established. Please press this option before initiating chat from another client or else program will crash.")
    #     lock.acquire(blocking=True, timeout=-1)
    #     if messy:
    #         print("This is the message thread.There is a small glitch please enter message again.")
    #     res=input()
    #     lock.release()
    #     if res=='a':
    #         listen_to_connections()
    #     if res=='b':
    #         connection_from_all_clients(c)
    #     elif res=='c':
    #         print('All conections up, moving to next stage')
    # while(res=='c'):
    #     generate_nonces()
    #     print("In main thread")
    #     print("choose client (enter name) for getting public key")
    #     for i in portlist.keys():
    #         if i!=name:
    #             print(i)
    #     lock.acquire(blocking=True, timeout=-1)
    #     recieve=input()
    #     lock.release()
    #     if recieve not in public_keys_list.keys():
    #         if recieve not in portlist.keys() or recieve==name:
    #             print("wrong input enter again")
    #             continue
    #         x,data = ask_key(c,recieve)
    #         public_keys_list[recieve]=data['public_key']
    #         if x==0:
    #             continue
    #         print("Initiating connection with "+recieve+".....")
    #         print()
    #         client_to=send_init_to_client(recieve,data['public_key'])
    #     else:
    #         print("Initiating connection with "+recieve+".....")
    #         print()
    #         client_to=send_init_to_client(recieve,public_keys_list[recieve])
    #     print("Wait for 100 seconds to communicate with another client")
    #     time.sleep(100)
    




    
        

            

        
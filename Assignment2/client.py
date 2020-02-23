import socket
import json

portlist={'client1':8080,'client2':8081}
portlist_clients={'client2':8082}
print("Enter your name")
name=input()
port=portlist[name]

def connect_server(port):
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect(('0.0.0.0', port))
    return client

def ask_key(client,receiver):
    request={'receiver':receiver,'time':"10"}
    client.send(json.dumps(request).encode('utf8'))
    from_server = client.recv(4096).decode('utf8')
    if(from_server=="0"):
        print("Wrong format.. breaking connection")
    elif (from_server=="client not found"):
        print("Server cannot find requested client")
    elif 'public_key' in json.loads(from_server):
        data=json.loads(from_server)
    client.close()


while True:
    print("a) Initiate connection")
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

        client=connect_server(port)
        ask_key(client,recieve)

            

        
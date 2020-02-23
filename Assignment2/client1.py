import socket
portlist={8080,8081}
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect(('0.0.0.0', 8081))
client.send("I am CLIENT2<br>".encode('utf8'))
from_server = client.recv(4096)
client.close()
print ("from_server")
    

        
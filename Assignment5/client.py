import socket
import pickle
import datetime
import random
import hmac
import hashlib
import json
from classes import decrypt1,encrypt1

send_s = socket.socket()
recv_s = socket.socket()

print("Socket created")
port1 = 34564
port2 = port1+1
#recv test message
recv_s.connect(('127.0.0.1',port1))
x = str(recv_s.recv(1024))
print(x)
#send test message
send_s.bind(('',port2))
send_s.listen(5)
serv,addr = send_s.accept()
serv.send(b'Im Bob')

print("done")
#--------------comms start here---------
name = input("Enter name")
year = input("Enter year")
month = input("Enter month")
day = input("Enter day")
#create datetime obj
date_inp = datetime.datetime(int(year),int(month),int(day))
#query -> {name,datetimeobj,query_type,nonce,timestamp,hmac}
my_nonce = random.randint(2,100)
my_time_stamp = datetime.datetime.now()
hmac_secret = b'12nsdn3@%'
#send hmac secret,encrypt first using client privkey then server pubkey
with open('./keys/client.private', 'rb') as priv2:
    priv_keyc = priv2.read()

with open('./keys/server.public', 'rb') as pub2:
    pub_keys = pub2.read()


#------encrypt---------------
temp_dict = {'sec' : hmac_secret}

temp=encrypt1(priv_keyc,temp_dict)
temp=encrypt1(pub_keys,temp)

serv.send(pickle.dumps(temp))
#-----encrypt---------------

#construct query
query_dict = {'name':name,'obj':date_inp,'qt':1,'nonce':my_nonce,'timestamp':my_time_stamp}
#append hmac
hmac_obj1 = hmac.new(hmac_secret,pickle.dumps(query_dict),hashlib.sha512)
query_dict['hmac'] = hmac_obj1.hexdigest()

#send query
#encypt first using client privkey then server pubkey
#-------encrypt--------
temp=encrypt1(priv_keyc,query_dict)
temp=encrypt1(pub_keys,temp)
serv.send(pickle.dumps(temp))
#-------encrpyt--------

#receive reply_dict
#decrypt first using client privkey then server pubkey
reply_dict = pickle.loads(recv_s.recv(4096))
temp=decrypt1(priv_keyc,query_dict)
temp=decrypt1(pub_keys,temp)
print(temp)
#verify hmac
received_hmac = reply_dict['hmac']
del reply_dict['hmac']
hmac_obj1.update(pickle.dumps(reply_dict))
if received_hmac==hmac_obj1.hexdigest():
    print("HMAC verified")

#verify nonce+queryType+timestamp
if my_nonce==reply_dict['nonce']:
    print("Nonce verified")

if my_time_stamp==reply_dict['timestamp']:
    print("Timestamp verifed")

if 1==reply_dict['qt']:
    print("Query type verified")

#done just print reply
print(reply_dict['reply'])
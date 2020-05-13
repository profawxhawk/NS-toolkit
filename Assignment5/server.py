import socket
import pickle
import datetime
import hmac
import hashlib

send_s = socket.socket()
recv_s = socket.socket()

print("Socket created")
port1 = 34564
port2 = port1+1
#bind and send test message
send_s.bind(('',port1))
send_s.listen(5)
client,addr = send_s.accept()
client.send(b'Im Alice')
#receive test message
recv_s.connect(('127.0.0.1',port2))
x = str(recv_s.recv(1024))
print(x)
print("done")
#--------communication starts here-------------
res = {'a':datetime.datetime(2000,4,20),'b':datetime.datetime(1999,2,12),'bnj':datetime.datetime(1970,1,1)}

#decrypt using server priv key followed by client pubkey
hmac_secret_dict = pickle.loads(recv_s.recv(4096))
hmac_secret = hmac_secret_dict['sec']

#receive query
#decrypt here, using priv key of server followed by client pubkey
query_dict = pickle.loads(recv_s.recv(4096))
print(query_dict)

#create hmac obj and verify hmac
received_hmac = query_dict['hmac']
del query_dict['hmac']
hmac_obj = hmac.new(hmac_secret,pickle.dumps(query_dict),hashlib.sha512)
if hmac_obj.hexdigest()==received_hmac:
    print("HMAC verified")

#check details in res and generate reply
reply = "NO"
if query_dict['name'] in res.keys():
    if query_dict['obj']==res[query_dict['name']]:
        reply="YES"

#construct reply dict ->{reply,querytype,nonce,timestamp,hmac}
reply_dict = {'reply':reply,'qt':query_dict['qt'],'nonce':query_dict['nonce'],'timestamp':query_dict['timestamp']}
#gen and append hmac
hmac_obj.update(pickle.dumps(reply_dict))
reply_dict['hmac'] = hmac_obj.hexdigest()

#send reply_dict
#encrypt using serverpriv , followed by client pubkey
client.send(pickle.dumps(reply_dict))

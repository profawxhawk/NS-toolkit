import os
import math
from AES import AES
def calc_size(filename):
    temp=os.path.getsize(filename)
    print("Size of file is "+str(temp)+" bytes")
    if math.ceil(temp/128)==1:
        print("Generating "+str(math.ceil(temp/128))+" block")
    else:
        print("Generating "+str(math.ceil(temp/128))+" blocks")

def get_blocks(f):
    blocks=[]
    while True:
        k=f.read(128)
        if k:
            blocks.append(k)
        else:
            break
    return blocks
if __name__ == '__main__':
    filename=input('Enter full path of file')
    f=open(filename,'r')
    calc_size(filename)
    blocks=get_blocks(f)
    Aes=AES(128,10,blocks)
    

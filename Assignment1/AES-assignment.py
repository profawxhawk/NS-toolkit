import os
import math
from AES import AES

# function to return size of file in bytes

def calc_size(blocks):
    temp=(len(blocks)-1)*(16)+(len(blocks[len(blocks)-1]))
    print("Size of file is "+str(temp)+" bytes")
    if math.ceil(temp/16)==1:
        print("Generating "+str(math.ceil(temp/16))+" block")
    else:
        print("Generating "+str(math.ceil(temp/16))+" blocks")

# function to return an array of 16-byte elements from a given open file descriptor ( not padded )

def get_blocks(f):
    blocks=[]
    while True:
        k=f.read(16)
        if k:
            blocks.append(str.encode(k))
        else:
            break
    return blocks

# function to pad last element of blocks array so that all the elements in the array have an uniform size of 16 bytes. ( uses pkcs5 padding )

def pad_block_PKCS5(blocks):
    if len(blocks[len(blocks)-1])!=16:
        blocks[len(blocks)-1]=(blocks[len(blocks)-1]+bytes([(16-len(blocks))]*(16-len(blocks))))

if __name__ == '__main__':
    filename=input('Enter full path of file')
    f=open(filename,'r')
    blocks=get_blocks(f)
    calc_size(blocks)
    pad_block_PKCS5(blocks)
    Aes=AES(128,10,blocks)
    Aes.encrypt()
    
    

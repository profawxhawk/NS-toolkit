import sys
class AES:
    key_size=0
    rounds=0
    state_vector=[]
    blocks_input=[]
    blocks_output=[]
    key_list=[]
    master_key=0
    def __init__(self,key_size,rounds,blocks):
        self.key_size=key_size
        self.rounds=rounds
        self.blocks_input=blocks

    def convert_to_state(self,input):
        state=[[],[],[],[]]
        count=0
        temp=[i.to_bytes(1, sys.byteorder) for i in input]
        for i in temp:
            state[count%4].append(i)
            count+=1
        return state
        
    def round_key_addition(index):
        pass

    def substitution_bytes():
        pass

    def shift_rows():
        pass

    def mix_columns():
        pass


    
    def encrypt_block(self,index):

        if(len(self.blocks_input[index])!=16):
            print("block size not 128 bites. exiting")
            exit(0)

        self.state_vector=self.convert_to_state(self.blocks_input[index])
        
        round_key_addition(0)

        for i in range(1,self.rounds+1):
            substitution_bytes()
            shift_rows()
            if i!=(self.rounds):
                mix_columns()
            round_key_addition(i)
            


    def encrypt(self):
        for i in range(len(self.blocks_input)):
            self.encrypt_block(i)



import sys

# AES class

class AES:
    key_size=0
    rounds=0
    state_vector=[]
    blocks_input=[]
    blocks_output=[]
    key_list=[]
    master_key=0

    # Initialise key_size, the entire message array ( each element is of size 16 bytes ) and number of rounds

    def __init__(self,key_size,rounds,blocks):
        self.key_size=key_size
        self.rounds=rounds
        self.blocks_input=blocks

    # Convert 1D 16 byte array to 2D 4*4 array
    def convert_to_state(self,input):
        state=[[],[],[],[]]
        count=0
        temp=[i.to_bytes(1, sys.byteorder) for i in input]
        for i in temp:
            state[count%4].append(i)
            count+=1
        return state

    # XOR sub-key ( indexed in the key_list array by the index parameter) with current state_vector
    def round_key_addition(index):
        pass
    
    # Use S-Box to do substitutions on each individual byte of the state_vector
    def substitution_bytes():
        pass
    
    # Shift the rows in the state_vector as in algorithm
    def shift_rows():
        pass
    
    # Multiply with mix_column matrix for transposing each individual column
    def mix_columns():
        pass


    # Main encryption function for each element of the message array
    def encrypt_block(self,index):

        if(len(self.blocks_input[index])!=16):
            print("block size s not 128 bites. exiting")
            exit(0)

        self.state_vector=self.convert_to_state(self.blocks_input[index])
        
        round_key_addition(0)

        for i in range(1,self.rounds+1):
            substitution_bytes()
            shift_rows()
            if i!=(self.rounds):
                mix_columns()
            round_key_addition(i)
            

    # CBC encryption for entire message
    def encrypt(self):
        for i in range(len(self.blocks_input)):
            self.encrypt_block(i)



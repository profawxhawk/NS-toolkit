import sys

# AES class

class AES:
    key_size=0
    rounds=0
    state_vector=[]
    blocks_input=[]
    blocks_output=[]
    sub_keys=[]
    master_key=0
    Mix_col_matrix=[2,1,1,3]
    Mix_col_matrix_inv=[14,11,13,9]
    arr_of_state = []
    arr_of_state_dec=[]
    d_sub_keys=[]
    # Rijndael S-box
    Rij_Sbox =  [
            [0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76], 
            [0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0],
            [0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15], 
            [0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75],
            [0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84],
            [0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf],
            [0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8],
            [0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2],
            [0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73],
            [0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb],
            [0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79],
            [0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08],
            [0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a],
            [0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e],
            [0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf],
            [0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16]]
    # Rijndael Inverse S-box
    Rij_inv_Sbox = [
            [0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb], 
            [0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb],
            [0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e], 
            [0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25], 
            [0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92],
            [0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84],
            [0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06],
            [0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b], 
            [0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73], 
            [0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e],
            [0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b],
            [0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4],
            [0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f],
            [0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef],
            [0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61],
            [0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d]]
    
    # Rcons for neccesary rounds
    Rij_rcon=[]
    
    
    # Initialise key_size, the entire message array ( each element is of size 16 bytes ) and number of rounds
    def __init__(self,key_size,rounds,blocks=[]):
        self.key_size=key_size
        self.rounds=rounds
        self.blocks_input=blocks
        temp=0x01
        for i in range(self.rounds):
            self.Rij_rcon.append(self.ith(temp))
            temp=self.galois_mult(temp,0x02)
            

    #setup for decryption
    def setup(self,blocks):
        self.blocks_input=blocks
        print(len(self.blocks_input[0]))

    # initialise master key
    def master_key_init(self,key):
        self.master_key=key

    # hex to int
    def hti(self,input):
        try:
            return int(input,16)
        except:
            return input

    # int to hex
    def ith(self,input):
        try:
            return format(input,'02x')
        except:
            return input

    # sub-key generation function
    def key_gen(self):
        self.master_key=self.convert_to_state(self.master_key)    # convert master key to 4*4 array 
        size=self.key_size//32
        temp=self.master_key
        prev=self.column(size-1,temp)                             # get the last column of master key
        self.sub_keys.append(self.master_key) 
        self.d_sub_keys.append(self.master_key)
        for i in range(self.rounds):
            sub_key=[]
            for j in range(size):                                 # generate 4 words for each round
                curr_column_in_prev=self.column(j,temp)           # get the word corresponding to the current index from the last round 
                output=[]
                if j==0:
                    prev=prev[1:]+prev[:1]                        # rotate the prev column
                    for x,y in enumerate(prev):
                        prev[x]=self.ith(self.Rij_Sbox[self.hti(y[0])][self.hti(y[1])])   # using sbox for substitution on prev column 
                    prev[0]=self.ith(self.hti(prev[0])^self.hti(self.Rij_rcon[i]))        # and then xoring with rcon of current round
                for x,y in zip(prev,curr_column_in_prev):
                    output.append(self.ith(self.hti(x)^self.hti(y)))                      # xor prev and the word corresponding to the current index from the last round 
                prev=output
                sub_key.append(output)                                                    # append generated word to the sub_key vector
            temp=[list(i) for i in zip(*sub_key)]
            temp2=[list(i) for i in zip(*sub_key)] 
            self.sub_keys.append(temp) 
            self.d_sub_keys.append(temp2)                                    # transpose the obtained sub_key vector and append it to global sub_keys vector
            
        # print(self.sub_keys)
        for i in range(1,self.rounds):
            self.inv_mix_columns_key(i)
        # print(self.sub_keys)

        


    # Convert 1D 16 byte array to 2D 4*4 array
    def convert_to_state(self,input):
        state=[[],[],[],[]]
        count=0
        for i in input:
            state[count%4].append(self.ith(i))   #convert to hex
            count+=1
        return state
    
    # Convert vector to hex string
    def vector_to_bytes(self,vector):
        output=''
        for i in range(4):
            for j in range(4):
                output+=self.state_vector[j][i]
        return bytes.fromhex(output)


    # Convert hex to (row,col) pair
    def get_index_from_hex(self,i,j):
        row=(self.state_vector[i][j][0])
        col=(self.state_vector[i][j][1])
        return self.hti(row),self.hti(col)

    # XOR sub-key ( indexed in the sub_keys array by the index parameter) with current state_vector
    def round_key_addition(self,index):
        for i in range(4):
            for j in range(4):
                self.state_vector[i][j]=self.ith(self.hti(self.state_vector[i][j])^self.hti(self.sub_keys[index][i][j]))
        
    def d_round_key_addition(self,index):
        for i in range(4):
            for j in range(4):
                self.state_vector[i][j]=self.ith(self.hti(self.state_vector[i][j])^self.hti(self.d_sub_keys[index][i][j]))
    
    # Use S-Box to do substitutions on each individual byte of the state_vector
    def substitution_bytes(self):
        for i in range(4):
            for j in range(4):
                row,col=self.get_index_from_hex(i,j)
                self.state_vector[i][j]=self.Rij_Sbox[row][col]


    def inv_sub_bytes(self):
        for i in range(4):
            for j in range(4):
                row,col=self.get_index_from_hex(i,j)
                self.state_vector[i][j]=self.ith(self.Rij_inv_Sbox[row][col])

    
    # Shift the rows in the state_vector as in algorithm
    def shift_rows(self):
        for i in range(1,4):
            self.state_vector[i]=self.state_vector[i][i:]+self.state_vector[i][:i]

    # i mean you know
    def inv_shift_rows(self):
        for i in range(1,4):
            self.state_vector[i]=self.state_vector[i][4-i:]+self.state_vector[i][0:4-i]

    
    # galois multiplication in GF(2^8)
    def galois_mult(self,a,b):
        p=0
        #print(b)
        for i in range(8):
            if a==0 or b==0:
                break
            if b&1:
                p=p^a
            b=b>>1
            carry=a&0x80
            a=a<<1
            if carry:
                a=a^(0x11B)
        return p

    # get the column of a vector by its column index
    def column(self,i,vector):  # ref
        return [row[i] for row in vector]
    

    # Multiply with mix_column matrix for transposing each individual column
    def mix_columns(self):
        for i in range(4):
            temp=self.column(i,self.state_vector)
            temp1=self.galois_mult(self.Mix_col_matrix[0],temp[0])^self.galois_mult(self.Mix_col_matrix[3],temp[1])^temp[2]^temp[3]
            temp2=self.galois_mult(self.Mix_col_matrix[0],temp[1])^self.galois_mult(self.Mix_col_matrix[3],temp[2])^temp[0]^temp[3]
            temp3=self.galois_mult(self.Mix_col_matrix[0],temp[2])^self.galois_mult(self.Mix_col_matrix[3],temp[3])^temp[0]^temp[1]
            temp4=self.galois_mult(self.Mix_col_matrix[0],temp[3])^self.galois_mult(self.Mix_col_matrix[3],temp[0])^temp[2]^temp[1]
            self.state_vector[0][i]=self.ith(temp1)
            self.state_vector[1][i]=self.ith(temp2)
            self.state_vector[2][i]=self.ith(temp3)
            self.state_vector[3][i]=self.ith(temp4)


    

    #Multiply with Mix_col_matrix_inv
    def inv_mix_columns(self):
        for i in range(4):
            temp = self.column(i,self.state_vector)
            temp1 = self.galois_mult(self.Mix_col_matrix_inv[0],self.hti(temp[0]))^self.galois_mult(self.Mix_col_matrix_inv[1],self.hti(temp[1]))^self.galois_mult(self.Mix_col_matrix_inv[2],self.hti(temp[2]))^self.galois_mult(self.Mix_col_matrix_inv[3],self.hti(temp[3]))
            temp2 = self.galois_mult(self.Mix_col_matrix_inv[3],self.hti(temp[0]))^self.galois_mult(self.Mix_col_matrix_inv[0],self.hti(temp[1]))^self.galois_mult(self.Mix_col_matrix_inv[1],self.hti(temp[2]))^self.galois_mult(self.Mix_col_matrix_inv[2],self.hti(temp[3]))
            temp3 = self.galois_mult(self.Mix_col_matrix_inv[2],self.hti(temp[0]))^self.galois_mult(self.Mix_col_matrix_inv[3],self.hti(temp[1]))^self.galois_mult(self.Mix_col_matrix_inv[0],self.hti(temp[2]))^self.galois_mult(self.Mix_col_matrix_inv[1],self.hti(temp[3]))
            temp4 = self.galois_mult(self.Mix_col_matrix_inv[1],self.hti(temp[0]))^self.galois_mult(self.Mix_col_matrix_inv[2],self.hti(temp[1]))^self.galois_mult(self.Mix_col_matrix_inv[3],self.hti(temp[2]))^self.galois_mult(self.Mix_col_matrix_inv[0],self.hti(temp[3]))
            self.state_vector[0][i]=self.ith(temp1)
            self.state_vector[1][i]=self.ith(temp2)
            self.state_vector[2][i]=self.ith(temp3)
            self.state_vector[3][i]=self.ith(temp4)
            

    def inv_mix_columns_key(self,indx):
        for i in range(4):
            temp = self.column(i,self.d_sub_keys[indx])           
            temp1 = self.galois_mult(self.Mix_col_matrix_inv[0],self.hti(temp[0]))^self.galois_mult(self.Mix_col_matrix_inv[1],self.hti(temp[1]))^self.galois_mult(self.Mix_col_matrix_inv[2],self.hti(temp[2]))^self.galois_mult(self.Mix_col_matrix_inv[3],self.hti(temp[3]))
            temp2 = self.galois_mult(self.Mix_col_matrix_inv[3],self.hti(temp[0]))^self.galois_mult(self.Mix_col_matrix_inv[0],self.hti(temp[1]))^self.galois_mult(self.Mix_col_matrix_inv[1],self.hti(temp[2]))^self.galois_mult(self.Mix_col_matrix_inv[2],self.hti(temp[3]))
            temp3 = self.galois_mult(self.Mix_col_matrix_inv[2],self.hti(temp[0]))^self.galois_mult(self.Mix_col_matrix_inv[3],self.hti(temp[1]))^self.galois_mult(self.Mix_col_matrix_inv[0],self.hti(temp[2]))^self.galois_mult(self.Mix_col_matrix_inv[1],self.hti(temp[3]))
            temp4 = self.galois_mult(self.Mix_col_matrix_inv[1],self.hti(temp[0]))^self.galois_mult(self.Mix_col_matrix_inv[2],self.hti(temp[1]))^self.galois_mult(self.Mix_col_matrix_inv[3],self.hti(temp[2]))^self.galois_mult(self.Mix_col_matrix_inv[0],self.hti(temp[3]))
            self.d_sub_keys[indx][0][i]=self.ith(temp1)
            self.d_sub_keys[indx][1][i]=self.ith(temp2)
            self.d_sub_keys[indx][2][i]=self.ith(temp3)
            self.d_sub_keys[indx][3][i]=self.ith(temp4)


    # Main encryption function for each element of the message array
    def encrypt_block(self,index):
        if(len(self.blocks_input[index])!=16):
            print("block size is not 128 bites. exiting")
            exit(0)

        self.state_vector=self.convert_to_state(self.blocks_input[index])
        self.round_key_addition(0)
        #print(self.state_vector)
        for i in range(4):
            self.arr_of_state.append([])
        for i in range(4):
            for j in range(4):
                self.arr_of_state[len(self.arr_of_state) - 4 + i].append(self.state_vector[i][j])
        #print(self.arr_of_state)
        #print("-------------------------------------")
        #print(self.state_vector)
        for i in range(1,self.rounds+1):
            self.substitution_bytes()
            self.shift_rows()
            if i!=(self.rounds):
                self.mix_columns()
            self.round_key_addition(i)
            #print(self.state_vector)
            if i==self.rounds:
                break
            for j in range(4):
                self.arr_of_state.append([])
            for k in range(4):
                for j in range(4):
                    self.arr_of_state[len(self.arr_of_state) - 4 + k].append(self.state_vector[k][j])
            #print(self.arr_of_state)
            #print("-------------------------------------")
            #print(self.state_vector)
        # print(self.arr_of_state)
        #print("----------------------------------------")
        
        

    def decrypt_block(self,index):

        if(len(self.blocks_input[index])!=16):
            print("block size is not 128 bites. exiting")
            exit(0)
        self.state_vector=self.convert_to_state(self.blocks_input[index])
        #print(self.state_vector)
        # for i in range(4):
        #     self.arr_of_state_dec.append([])
        # for i in range(4):
        #     for j in range(4):
        #         self.arr_of_state_dec[len(self.arr_of_state_dec) - 4 + i].append(self.state_vector[i][j])
        #print(self.arr_of_state_dec)
        self.round_key_addition(self.rounds)
        #print("---------------------------")
        #self.arr_of_state_dec.append(self.state_vector)
        for i in range(self.rounds-1,0,-1):
            #print(i)
            self.inv_shift_rows()
            self.inv_sub_bytes()
            #print(self.state_vector)
            
            for k in range(4):
                self.arr_of_state_dec.append([])
            for k in range(4):
                for j in range(4):
                    self.arr_of_state_dec[len(self.arr_of_state_dec) - 4 + k].append(self.state_vector[k][j])
            #print(self.arr_of_state_dec)
            #print("----------------------")
            self.round_key_addition(i) 
            self.inv_mix_columns()
            
                       
            #self.arr_of_state_dec.append(self.state_vector)
            
        self.inv_shift_rows()
        self.inv_sub_bytes()
        #print(self.state_vector)
        for k in range(4):
            self.arr_of_state_dec.append([])
        for k in range(4):
            for j in range(4):
                self.arr_of_state_dec[len(self.arr_of_state_dec) - 4 + k].append(self.state_vector[k][j])
        #print(self.arr_of_state_dec)
        #print("----------------------")
        #       
        self.round_key_addition(0)
        #self.arr_of_state_dec.append(self.state_vector)
        


        # print(self.arr_of_state_dec)

    #xor 2 hex strings
    def xor_hex(self,a,b):
        for i,j in zip(a,b):
            #print(j)
            i=self.ith(i^j)

    def conver_to_byte(self):
        temp=""
        for i in range(0,4):
            for j in range(0,4):
                temp=temp+self.state_vector[j][i]
        temp =str.encode(temp)
        return temp
    # CBC encryption for entire message
    def encrypt(self):
        iv=b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
        prev=iv
        output=[]
        for i in range(len(self.blocks_input)):
            if i==0:
                self.xor_hex(self.blocks_input[i],(prev))
                self.encrypt_block(i)
                prev=self.state_vector
                output.append(self.vector_to_bytes(prev))
            else:
                self.xor_hex(self.blocks_input[i],self.conver_to_byte())
                self.encrypt_block(i)
                prev=self.state_vector
                output.append(self.vector_to_bytes(prev))
            
        print("Encryption done returning to main. See encrypt.txt for encrypted text.")
        print(b''.join(output))
        return  b''.join(output)

    #CBC decryption
    def decrypt(self):
        output=[]
        iv=b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
        prev=(iv)
        for i in range(len(self.blocks_input)):    
            self.decrypt_block(i)
            #print(self.blocks_input[i])
            output.append(self.vector_to_bytes(self.xor_hex(prev,self.conver_to_byte())))
            prev=self.blocks_input[i]
            #print(output[len(output)-1])
        #print(len(b''.join(output)))

        last = list(output[len(output)-1])
        #print(last)
        x = len(last)
        pad=(last[x-1])
        if(pad<=15):
            for i in range(x-1,x-1-pad+1,-1):
                if(last[i]!=last[i-1] and pad!=1):
                    pad=0
                    break
        else:
            pad=0
        last = last[0:len(last)-pad]
        #print(last)
        for i in range(len(last)):
            last[i] = bytes([last[i]])
        temp=b''.join(last)
        #print(last)
        #print(temp)
        #
        #temp = str.encode(temp)
        output = output[0:len(output)-1]
        
        output.append(temp)
        #print(output)
        #assert encryption rounds
        f=True
        # print(self.arr_of_state)
        # # print("--------------------")
        # print(self.arr_of_state_dec)
        # print(self.arr_of_state)
        n = len(self.arr_of_state_dec)
        print(n)
        indx=40-4
        v1=40
        prev=0
        for i in range(0,len(self.arr_of_state),4):
            if i-prev==40:
                prev=i
                v1=v1+40
                indx=v1-4
            for j in range(0,4):
                print(i+j,indx+j)
                lis1 = self.arr_of_state[i+j]
                lis2 = self.arr_of_state_dec[indx+j]
                print(lis1,lis2)                
                assert lis1==lis2,"Error, encryption not equal to decryption"
            indx = indx - 4
        print('-------------------')
        self.arr_of_state = []
        self.arr_of_state_dec=[]
                

        


        # for i in range(0,len(self.arr_of_state)):
        #     for j in range(0,len(self.arr_of_state[i])):                
        #         for k in range(0,len(self.arr_of_state[i][j])):
        #             print(self.hti(self.arr_of_state[i][j][k]),self.hti(self.arr_of_state_dec[len(self.arr_of_state)-i-1][j][k]))
        #             if self.arr_of_state[i][j][k]!=self.arr_of_state_dec[len(self.arr_of_state)-i-1][j][k]:
        #                 f=False
        #                 break
        # if f==True:
        #     print("All rounds Matched")
        # else:
        #     print("Crap")
        print(output)
        return b''.join(output)



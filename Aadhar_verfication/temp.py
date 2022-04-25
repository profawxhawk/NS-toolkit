def reverseString(s):
        if len(s)<=1:
            return 
        reverseString(s[1:-1])
        temp=s[0]
        s[0]=s[-1]
        s[-1]=temp


s=["h","e","l","l","o"]
reverseString(s)
print(s)
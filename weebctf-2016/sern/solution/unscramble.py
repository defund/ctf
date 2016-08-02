import sys
sys.setrecursionlimit(2000)
def match(x,y):
    x = bin(ord(x))[-6:]
    y = bin(ord(y))[-6:]
    same = True
    for i in range(6):
        if x[i]==y[i] and not same:
            return False
        elif x[i]!=y[i] and same:
            same = False
    return True

f = open('result.txt','r')
d = f.read()
f.close()

def step(d,s,ci):
    for i in range(len(s)):
        if not match(s[i],d[len(d)-1-i]):
            return None
    if len(s) == 1600:
        print('done')
        f = open('unscrambled.txt','w')
        f.write(s+d[1600:])
        f.close()
        return None
    for i in range(ci,ci+20):
        if match(d[i],d[len(d)-1-ci]):
            t = d[ci:i+1]
            t = t[-1:]+t[:-1]
            step(d,s+t,i+1)
step(d,'',0)

    
    

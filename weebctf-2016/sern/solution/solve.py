def swap(c):
    if c == '0':
        return '1'
    return '0'

def solve(x,y,px,py,cx,cy,p1,p2):
    if x == '0' and y == '0':
        px += p1
        py += p2
        if cx == '' and cy == '': return [[px,py]]
        return solve(cx[0],cy[0],px,py,cx[1:],cy[1:],x,y)
    elif x == '1' and y == '1':
        px += swap(p1)
        py += swap(p2)
        if cx == '' and cy == '': return [[px,py]]
        return solve(cx[0],cy[0],px,py,cx[1:],cy[1:],x,y)
    elif x == '0' and y == '1':
        if p1 == p2:
            px += '0'
            py += '1'
            if cx == '' and cy == '': return [[px,py]]
            return solve(cx[0],cy[0],px,py,cx[1:],cy[1:],x,y)
        else:
            if p1 == '0' and p2 == '1':
                if cx == '' and cy == '': return [[px+'0',py+'1'],[px+'0',py+'0']]
                return solve(cx[0],cy[0],px+'0',py+'1',cx[1:],cy[1:],x,y) + solve(cx[0],cy[0],px+'0',py+'0',cx[1:],cy[1:],x,y)
            elif p1 == '1' and p2 == '0':
                if cx == '' and cy == '': return [[px+'0',py+'1'],[px+'1',py+'1']]
                return solve(cx[0],cy[0],px+'0',py+'1',cx[1:],cy[1:],x,y) + solve(cx[0],cy[0],px+'1',py+'1',cx[1:],cy[1:],x,y)
    elif x == '1' and y == '0':
        if p1 == p2:
            px += '1'
            py += '0'
            if cx == '' and cy == '': return [[px,py]]
            return solve(cx[0],cy[0],px,py,cx[1:],cy[1:],x,y)
        else:
            if p1 == '1' and p2 == '0':
                if cx == '' and cy == '': return [[px+'1',py+'0'],[px+'0',py+'0']]
                return solve(cx[0],cy[0],px+'1',py+'0',cx[1:],cy[1:],x,y) + solve(cx[0],cy[0],px+'0',py+'0',cx[1:],cy[1:],x,y)
            elif p1 == '0' and p2 == '1':
                if cx == '' and cy == '': return [[px+'0',py+'1'],[px+'1',py+'1']]
                return solve(cx[0],cy[0],px+'1',py+'0',cx[1:],cy[1:],x,y) + solve(cx[0],cy[0],px+'1',py+'1',cx[1:],cy[1:],x,y)

def main(a,b):
    ba = bin(ord(a))
    bb = bin(ord(b))
    array = solve(ba[-6],bb[-6],'01','01',ba[-5:],bb[-5:],'1','1')
    array = [[chr(int(y,2)) for y in x] for x in array]
    return array

f = open('unscrambled.txt','r')
d = f.read()
f.close()
p = []
for i in range(len(d)):
    p.append([x[0] for x in main(d[i],d[len(d)-1-i])])
o = []
for i in range(len(p)-5):
    if 'w' in p[i] and 'e' in p[i+1] and 'e' in p[i+2] and 'b' in p[i+3] and '{' in p[i+4]:
        for j in range(i,len(p)):
            if j-i > 34:
                break
            if '}' in p[j] and j-i+1 == 24:
                o.append('\n'.join([''.join(list(set(x))) for x in p[i:j+1]]))
f = open('poss.txt','w')
f.write('\n----------\n'.join(o))
f.close()
    

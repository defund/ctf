f = open('data','r')
d = f.read()
f.close()

o = ''
while len(d) != 0:
    d = d[16:]
    d = d[159:]
    o += d[:1764]
    d = d[1764:]

f = open('raw','w')
f.write(o)
f.close()

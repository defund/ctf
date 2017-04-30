f = open('dump.elf','r')
raw = f.read()
f.close()

key1 = 'properties for \'FONT_OT_delete\'\nbpy.ops.font.text_insert(text="'
key2 = 'properties for \'FONT_OT_text_insert\'\nbpy.ops.font.text_insert(text="'

o = ''

d = raw
while key1 in d:
    i = d.index(key1)+len(key1)
    o += d[i]
    d = d[i:]
d = raw
while key2 in d:
    i = d.index(key2)+len(key2)
    o += d[i]
    d = d[i:]

f = open('out.txt','w')
f.write(o)
f.close()

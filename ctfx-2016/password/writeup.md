files.zip contains two encrypted ZIP files. Both zip files contain 
a vcard and a signature of an employee.

Evelyn Davis.zip can be cracked with a dictionary attack:
password = basher

The vcard inside her files is predictable:

BEGIN:VCARD
VERSION:3.0
N:Davis;Evelyn;;;
FN:Evelyn Davis
ORG:Defund Corp;
EMAIL;type=INTERNET;type=WORK;type=pref:evelyn.davis@defund.io
END:VCARD

Using that as a template, a vcard for Ryan King can be constructed:

BEGIN:VCARD
VERSION:3.0
N:King;Ryan;;;
FN:Ryan King
ORG:Defund Corp;
EMAIL;type=INTERNET;type=WORK;type=pref:ryan.king@defund.io
END:VCARD

Ryan King.zip can be cracked with a plaintext attack using a tool
such as pkcrack.

Ryan King's signature is the flag.
List the active processes in the memory dump:

./volatility_2.5_mac -f ~/Desktop/dump --profile=Win7SP0x86 pslist

The important ones are these:

0x85b4b580 TrueCrypt.exe          2852    592     11      304      1      0 2016-08-22 21:45:34 UTC+0000                                 
0x858b0248 notepad.exe            3228   3196      2       61      1      0 2016-08-22 21:46:30 UTC+0000                                 
0x85bb8030 iexplore.exe           3256    592     24      469      1      0 2016-08-22 21:46:41 UTC+0000                                 
0x85ba9258 iexplore.exe           3340   3256     25      627      1      0 2016-08-22 21:46:44 UTC+0000

Scan for files to find any file containers encrypted with TrueCrypt:

./volatility_2.5_mac -f ~/Desktop/dump --profile=Win7SP0x86 filescan

A file container is in the Desktop/ folder:

0x000000001e4872b0      5      0 R--rw- \Device\HarddiskVolume2\Users\IEUser\Desktop\ripme

Dump this file:

./volatility_2.5_mac -f ~/Desktop/dump --profile=Win7SP0x86 dumpfiles -Q 0x000000001e4872b0 -D ~/Desktop/

Extract the TrueCrypt passphrase from the memory dump:

./volatility_2.5_mac -f ~/Desktop/dump --profile=Win7SP0x86 truecryptpassphrase
Volatility Foundation Volatility Framework 2.5
Found at 0x8c78de44 length 32: 7WlsCP6ZA79LAdbdYov4i7HLh165BJcw

Download TrueCrypt online and extract the files from the container, the public and private keys.

Show the internet history:

./volatility_2.5_mac -f ~/Desktop/dump --profile=Win7SP0x86 iehistory

The important link is this:

**************************************************
Process: 3256 iexplore.exe
Cache type "URL " at 0x1e25880
Record length: 0x180
Location: Visited: IEUser@http://pastebin.com/8XSj5NJP
Last modified: 2016-08-22 21:43:11 UTC+0000
Last accessed: 2016-08-22 21:43:11 UTC+0000
File Offset: 0x180, Data Offset: 0x0, Data Length: 0x98
**************************************************

Download the encrypted message. A possible passphrase for the pgp encryption is the password to the actual computer. 
Display cached hives:

./volatility_2.5_mac -f ~/Desktop/dump --profile=Win7SP0x86 hivelist

The addresses we need are system and SAM:

0x87a1c008 0x1ba38008 \REGISTRY\MACHINE\SYSTEM
0x928c8008 0x124ae008 \SystemRoot\System32\Config\SAM

Dump the NTLM hashes:

./volatility_2.5_mac -f ~/Desktop/dump --profile=Win7SP0x86 hashdump -y 0x87a1c008 -s 0x928c8008

Take the IEUser hash and crack it online:

IEUser:1000:aad3b435b51404eeaad3b435b51404ee:83c3399edaae7fc957a9041d11810da8:::

The password is 'potato'. Decrypt the pgp message to get the flag.

Note: you can also directly crack the pgp passphrase with something like John the Ripper.






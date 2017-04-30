See my previous writeup for pgp in CTF(x) 2016 if you aren't comfortable with volatility. This is also a good reference whenever you deal with memory dumps:
https://downloads.volatilityfoundation.org//releases/2.4/CheatSheet_v2.4.pdf

Listing the files shows that there is a file that we can extract:
0xffff880028f00cd8                   1835316 /tmp/quit.blend

/tmp/quit.blend is a recovery file that Blender stores whenever you exit without saving your model file. However, it seems like there isn't any useful information in it except for a message defund left behind:
close, but no cigar :)

Recovering bash history shows that defund called Blender from the command line, along with a debug flag. Running Blender in this debug mode means that many user actions, such as keyboard typing or mouse clicking, are logged and outputted in stdout. Plugins most likely exist to extract stdout, but you can also try to extract the keys typed directly from the memory dump. Source code is in source/.

Depending on what you used to detect logged output, you will get some type of output like this:
actf{blend_in_ar :)ar :)close, but no c :)arar :)with_the_debug}

Combining this info with the previous message from /tmp/quit.blend makes it easy to deduce the flag.

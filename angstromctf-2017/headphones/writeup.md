Ignore all packets sent from 1.3.5 (headphones) to host (computer).

Wireshark labels which section of each packet is the USB URB header. Documentation about the format:

https://msdn.microsoft.com/en-us/library/windows/hardware/ff537056(v=vs.85).aspx

Extract all of the data after the header, which is raw PCM audio. Source code is available in source/.

Convert the raw audio into a format that audio players can understand using ffmpeg or Audacity. The parameters don't have to be perfect since you just need to be able to understand the flag.
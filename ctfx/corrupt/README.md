The IDAT chunk that is corrupted is missing 4 bytes, as shown by the difference between the given and actual length. 

To fix the image, force the data to match its crc32 hash. Find the offset by either bashing or locate where the zlib stream meets an error.

The flag is displayed in the bottom half of the recovered image.
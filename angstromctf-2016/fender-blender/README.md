Install Blender 2.74 and open the file.

The easiest way to get all 5000 frames is to run the animation in Blender; all frames will be in the /tmp folder.
Alternatively, you can render frames through command line:

/Applications/blender.app/Contents/MacOS/blender -b ufo.blend -o // -f /<frame number/>

With all of the frames, you can grep data from each image to determine the frame numbers.
Comparing pixel data is also a valid way to compare frames and get the flag:

flag{263,1337,3333,3999,4545}

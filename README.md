This is a simple buffer overflow helper script I originally wrote to make the process faster for the OSCP.

This script automates initial overflow, offset discovery, bad character detection, and shellcode script generation. You just have to push a couple buttons and find the address of the instruction you want to jump to. And if if the exploitation process is more complex than that, it writes the shellcode script to a file for you to edit and fix all the non-trivialities (may be updated in the future to automate some non-trivialities). e.g. If you need to execute custom instructions (like modifying the stack pointer and jumping to it) before your shellcode, you're going to have to add that manually. If you use this on the OSCP exam, be careful. I don't consider it an automatic exploitation tool yet (though I may eventually create a fully-automated tool), but keep in mind that this is a _helper_ script meant to take care of some of the more tedious processes for you behind the scenes. You still need to interact with your debugger and understand how these overflows work conceptually. Ensuring that information is clearly communicated in your report is your responsibility.


<br />

usage: BofHelper.py [-h] [-o FILE] [-b] [-p PREFIX] [-s SUFFIX] host port
<br />

positional arguments:

  host &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;The host executing the vulnerable application (usually
                        your debugger)
                        
  port &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;The port the application is running on

<br />

optional arguments:

  -h, --help &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;show this help message and exit
  
  -o FILE, --output FILE &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Write payload script to FILE
                        
  -b, --badchars &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; Attempt to detect bad characters with your debugger of choice
  
  -p PREFIX, --prefix PREFIX &nbsp;&nbsp;&nbsp;Append a prefix to the beginning of your overflow string
                        
  -s SUFFIX, --suffix SUFFIX &nbsp;&nbsp;&nbsp;Append a suffix to the end of your overflow string

<br /><br />

Example: ./BofHelper.py -o exploit.py -b -p 'USER ' 127.0.0.1 9001

IMPORTANT: 

If you use the bad character detection option, please ensure there are at least two spaces between the dump address and your actual memory, as well as between your memory and the ASCII representation. e.g.

0x012345678 &nbsp;14 15 16 17 18 19 20 21&nbsp; ABCDEFGH

I may modify the regex in the future to make this more robust, but for the time being, you have to extend your dump output margins in some debuggers. Olly formats it correct by default.

Be sure to paste your data dump every time it asks because fixing a bad character could lead to new bad characters being discovered. In order to mitigate this, the script loops the detection process until all bad characters have been discovered.

Also, when generating your shellcode with venom, you HAVE to use the -f py option or it will fail to generate. This will be automated in the future (along with automatically adding the bad characters), but for right now, you have to pretend you're running the command directly in the console. 

<br /><br />

Example video coming soon!

<br /><br />

License TL;DR:
Use this script wherever you want, however you want, but include a link to https://YouTube.com/LegendBegins whenever you distribute it. All my content is gaming related, but I figured this was as good a place as any to advertise.

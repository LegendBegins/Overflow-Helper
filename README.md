This is a simple buffer overflow helper script I originally wrote to make the process faster for the OSCP.

This script automates initial overflow, offset discovery, bad character detection, and shellcode script generation. You just have to push a couple buttons and find the address of the instruction you want to jump to. And if if the exploitation process is more complex than that, it writes the shellcode script to a file for you to edit and fix all the non-trivialities (may be updated in the future to automate some non-trivialities). e.g. If you need to execute custom instructions (like modifying the stack pointer and jumping to it) before your shellcode, you're going to have to add that manually.

<br />

usage: BofHelper.py [-h] [-o FILE] [-b] [-p PREFIX] [-s SUFFIX] host port
<br />

positional arguments:
  host                  The host executing the vulnerable application (usually
                        your debugger)
  port                  The port the application is running on

<br />

optional arguments:
  -h, --help            show this help message and exit
  -o FILE, --output FILE
                        Write payload script to FILE
                        
  -b, --badchars        Attempt to detect bad characters with your debugger of choice
  -p PREFIX, --prefix PREFIX
                        Append a prefix to the beginning of your overflow string
  -s SUFFIX, --suffix SUFFIX
                        Append a suffix to the end of your overflow string

<br /><br />
IMPORTANT: 

If you use the bad character detection option, please ensure there are at least two spaces between the dump address and your actual memory, as well as between your memory and the ASCII representation. e.g.

0x012345678 &nbsp;00 00 00 00 00 00 00 00&nbsp; ........

I may modify the regex in the future to make this more robust, but for the time being, you have to extend your dump output margins in some debuggers. Olly formats it correct by default.

<br /><br />

Example video coming soon!

<br /><br />

License TL;DR:
Use this script wherever you want, however you want, but include a link to https://YouTube.com/LegendBegins whenever you distribute it. All my content is gaming related, but I figured this was as good a place as any to advertise.

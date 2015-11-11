# Notes
Remove HTTP header for image

## IP header
IP Protocol 6 (TCP)
IP Flags 0x02 (Don't Fragment)
IP Length: 20

## TCP Header
Source Port      16 bits
Destination Port 16 bits
Sequence number  32 bits
Ack nr           32 bits
Header length     4 bits
Reserved          4 bits
Flags             8 bits
Window size      16 bits
Checksum         16 bits
Urgent pt        16 bits
Options          12 bytes

Total: 32 bytes

Header length = 4 bit number  * 4

## TCP Data
First is HTTP response
Stating that it is a JPEG.

## Image info JPEG
\r\n = 0d 0a
Start of image 0xffd8


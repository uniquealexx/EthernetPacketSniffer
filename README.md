This program captures Ethernet packets from a specified network interface and displays their contents on the terminal. The IP or MAC addresses of the source and destination are highlighted in bold. The output format is 32 bytes per line, with each byte represented in hexadecimal. The program uses raw sockets for packet reception.

Input parameters: -i -s <ip | mac> - specifies which addresses to highlight.

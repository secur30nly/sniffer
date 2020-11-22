# Sniffing of raw-sockets

# 1. Parts of project
+ headerStructs.c
  >All protocol headers structures
 
+ combineProto.c
  >L2-L3 protocol combination (IPv4-ICMP, IPv4-TCP, ARP-ARP and others)
 
+ decoders.c
  >Decoding of all protocol headers
  
+ dataHandlers.c
  >Module with different functions
  
+ main.c
  >Main C-file
  
+ makefile
  >Automatic assembly from object files
  
+ modificators.c
  >Modification of the protocol header fields for further forwarding (if you need it)
  
+ modifyHandler.c
  >Interface to manage protocol header modifications
  
+ references.c
  >Connecting the required libraries and declaration of all functions
 
+ progAssembly.sh
  >Quick build bash-script
  
# 2. Installation
Installation for sniffer state-machine and just sniffer is the same.
+ 1. Install libpcap-dev
>
    >>> sudo apt install libpcap-dev

+ 2. Download project
>
    >>> git clone https://github.com/RuslanGajiev/sniffer.git

+ 3. Open the directory with project files and run the makefile to build sniffer
>
    >>> make -f makefile

+ 4. Clean your directory of object-files
>
    >>> make clean

+ 5. Run your sniffer with sudo(raw-sockets require it)
>
    >>> sudo ./sniffer
    
+ Or run ./progAssembly.sh and execute sniffer.


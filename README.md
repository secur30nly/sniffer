# Sniffing of raw-sockets

# 1. Parts of project
+ all_structs.c
  >All protocol headers structures
 
+ combineprot.c
 >L2-L3 protocol combination (IPv4-ICMP, IPv4-TCP, ARP-ARP and others)
 
+ decoders.c
  >Decoding of all protocol headers
  
+ dumptraffic.c
 >Function for dump-traffic
  
+ main.c
  >Main C-file
  
+ makefile
  >Automatic assembly from object files
  
+ modificators.c
  >Modification of the protocol header fields for further forwarding (if you need it)
  
+ modify_manage.c
  >Interface to manage protocol header modifications
  
+ references.c
  >Connecting the required libraries and declaration of all functions
  
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

+ 5. Run your sniffer(sudo only)
>
    >>> sudo ./sniffer

# Note: The MAC-address and ip address of the host are not set by default. You can set them in the references.c file in the HOST_IP and HOST_MAC fields.


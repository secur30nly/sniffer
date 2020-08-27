# sniffing of raw-sockets

# 1. Installation
Installation for sniffer state-machine and just sniffer is the same.
+ all_structs.c
  >All protocol headers structures
 
+ combineprot.c
 >L2-L3 protocol combination (IPv4-ICMP, IPv4-TCP, ARP-ARP and others)
 
+decoders.c
  >Decoding of all protocol headers
  
+dumptraffic.c
 >Function for dump-traffic
  
+main.c
  >Main C-file
  
+makefile
  >Automatic assembly from object files
  
+modificators.c
  >Modification of the protocol header fields for further forwarding (if you need it)
  
+modify_manage.c
  >Interface to manage protocol header modifications
  
+references.c
  >Connecting the required libraries and declaration of all functions

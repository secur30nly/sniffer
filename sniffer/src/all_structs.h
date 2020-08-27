#define SADNESS 1    
#define DATA_BUFFER_SIZE 1460
#define ETHER_ADDR_LEN 6   
#define ETHER_HEAD_LEN 14      
#define ETH_P_ALL 0x0003
#define TCP_FIN 0x01
#define TCP_SYN 0x02
#define TCP_RST 0x04 
#define TCP_PUSH 0x08
#define TCP_ACK 0x10
#define TCP_URG 0x20
#define IP_DF 0x4000      
#define IP_MF 0x2000      


/*All protocol header structures*/


typedef struct ARP_Header{
          unsigned short arp_mac_type;
          unsigned short arp_prot_type;
          unsigned char arp_mac_size;
          unsigned char arp_prot_size;
          unsigned short op_code; 
          unsigned char arp_src_mac[ETHER_ADDR_LEN];
          unsigned char arp_src_ip[4];
          unsigned char arp_dst_mac[ETHER_ADDR_LEN];
          unsigned char arp_dst_ip[4];
}ARP_HDR;


typedef struct IP_Header{                                                                                                                                                                                                                  
          unsigned char ip_ihl:4;                                                                                                                                                                                                          
          unsigned char ip_ver:4;                                                                                                                                                                                                          
          unsigned char ip_type_os;                                                                                                                                                                                                        
          unsigned short ip_len;                                                                                                                                                                                                           
          unsigned short ip_id;                                                                                                                                                                                                            
          unsigned short ip_off;                                                                                                                                                                                                           
          unsigned char ip_ttl;                                                                                                                                                                                                            
          unsigned char ip_type_prot;                                                                                                                                                                                                      
          unsigned short ip_sum;                                                                                                                                                                                                           
          unsigned int ip_source;                                                                                                                                                                                                          
          unsigned int ip_dest;                                                                                                                                                                                                            
}IP_HDR;                                                                                                                                                                                                                                   
                                                                                                                                                                                                                                           
                                                                                                                                                                                                                                           
                                                                                                                                                                                                                                           
typedef struct ICMP_Header                                                                                                                                                                                                                 
{                                                                                                                                                                                                                                          
          unsigned char icmp_type_msg;                                                                                                                                                                                                     
          unsigned char icmp_code_msg;                                                                                                                                                                                                     
          unsigned short icmp_checksum;                                                                                                                                                                                                    
          unsigned short id;
          unsigned short seq;
}ICMP_HDR;

typedef struct IGMP_Header
{
          unsigned char igmp_type;
          unsigned char igmp_code;
          unsigned short igmp_checksum;
          unsigned int igmp_group;
}IGMP_HDR;



typedef struct Ether_Header 
{
         unsigned char   ether_dst_addr[ETHER_ADDR_LEN];
         unsigned char ether_src_addr[ETHER_ADDR_LEN];
         unsigned short ether_type;
}ETHER_HDR;



typedef struct UDP_Header
{
          unsigned short udp_src_port;
          unsigned short udp_dst_port;
          unsigned short udp_len;
          unsigned short udp_checksum;
}UDP_HDR;



typedef struct TCP_Header
{
          unsigned short tcp_src_port;
          unsigned short tcp_dest_port;
          unsigned int tcp_seq;
          unsigned int tcp_ack; 
          unsigned char reserved:4;
          unsigned char tcp_offset:4; 
          unsigned char tcp_flags; 
          unsigned short tcp_window; 
          unsigned short tcp_checksum;
          unsigned short tcp_urgent;
}TCP_HDR;



enum Protocols {
        IPv4 = 0x0800,
        ARP = 0x0806,
        WAKE_ON_LAN = 0x0842,
        RARP = 0x8035,
        AARP = 0x80F3,
        VLAN_TAGGED = 0x8100,
        IPx = 0x8137,
        IPv6 = 0x86DD,
        VLAN_DOUBLE_TAGGED = 0x9100
};


enum IP_Type_Prot{
        IP = 0,
        ICMP = 1,
        IGMP = 2,
        TCP = 6,
        UDP = 17
};


enum Types_icmp_msg{
        ICMP_echoreply = 0,
        ICMP_DEST_UNREACH = 3,
        ICMP_SOURCE_QUENCH = 4,
        ICMP_REDIRECT = 5,
        ICMP_ECHO = 8,
        ICMP_TIME_EXCEEDED = 11,
        ICMP_PARAMETERPROB = 12,
        ICMP_TIMESTAMP = 13,
        ICMP_TIMESTAMPREPLY = 14,
        ICMP_INFO_REQUEST = 15,
        ICMP_INFO_REPLY = 16,      
        ICMP_ADDRESS = 17,      
        ICMP_ADDRESSREPLY = 18      
};


enum Codes_icmp_msg{
        ICMP_NET_UNREACH = 0,       
        ICMP_HOST_UNREACH = 1,       
        ICMP_PROT_UNREACH = 2,       
        ICMP_PORT_UNREACH = 3,       
        ICMP_FRAG_NEEDED = 4,       
        ICMP_SR_FAILED = 5,       
        ICMP_NET_UNKNOWN = 6,
        ICMP_HOST_UNKNOWN = 7,
        ICMP_HOST_ISOLATED = 8,
        ICMP_NET_ANO = 9,
        ICMP_HOST_ANO = 10,
        ICMP_NET_UNR_TOS = 11,
        ICMP_HOST_UNR_TOS = 12,
        ICMP_PKT_FILTERED = 13,      
        ICMP_PREC_VIOLATION = 14,      
        ICMP_PREC_CUTOFF = 15 
};

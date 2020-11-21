#ifndef PREFERENCES_H
#define PREFERENCES_H

#include <stdio.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <pcap.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ctype.h>
#define IP_ADDR_LEN 4
#define HOST_IP "192.168.0.3"
#define HOST_MAC "\x34\xe1\x2d\xfc\xf3\xaa"

	void next_protocol_for_ip4(unsigned char *buffer,const unsigned int lenght);
	void if_ARP(const unsigned char *buffer,const unsigned int lenght);
	unsigned int decode_arp_hdr(const unsigned char *begin_header);
	void decode_eth_hdr(const unsigned char *begin_header);
	unsigned int decode_ip_hdr(const unsigned char *begin_header);
	unsigned int decode_tcp_hdr(const unsigned char *begin_header);
	unsigned int decode_udp_hdr(const unsigned char *begin_header);
	unsigned int decode_igmp_hdr(const unsigned char *begin_header);
	unsigned int decode_icmp_hdr(const unsigned char *begin_header);
	void dumptraffic(const unsigned char *data_buffer, const unsigned int length);
	void ip_proto_modify(const unsigned char *header_start);
	void icmp_proto_modify(unsigned char *buffer,const unsigned int lenght,unsigned char **arg_vctr);
	int ether_head_modify(const unsigned char *header_start);
	void tcp_proto_modify(const unsigned char *header_start);
	void udp_proto_modify(const unsigned char *header_start);
	void arp_proto_modify(const unsigned char *header_start);
	void modification(unsigned char *buffer,const unsigned int lenght,unsigned char **arg_vector);
	void if_have_tcp_udp(const unsigned char *buffer);
	void STATE_ICMP(unsigned char *buffer,const unsigned int lenght,int socket,unsigned char **arg_vector);
	void STATE_ARP(unsigned char *buffer,const unsigned int lenght,int socket);
	void STATE_IP(unsigned char *buffer,const unsigned int lenght,int socket);
	void STATE_TCP(unsigned char *buffer,const unsigned int lenght,int socket);
	void STATE_UDP(unsigned char *buffer,const unsigned int lenght,int socket);
	void STATE_IGMP(unsigned char *buffer,const unsigned int lenght,int socket);

	#endif

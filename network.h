#ifndef NETWORK_H
#define NETWORK_H

#include <stdio.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

struct Packet {
	struct timeval ts;
	int proto;
	uint16_t d_port;
	uint32_t d_ip;
	uint16_t s_port;
	uint32_t s_ip;
	int pkt_size;
	int pl_size;
	const u_char *payload;
};

int packet_parse(const u_char *data, Packet *packet, int len);
void printPacket(Packet *pkt);

#endif

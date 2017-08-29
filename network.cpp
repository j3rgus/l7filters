#include "network.h"

void printPacket(Packet *pkt)
{
	printf("\nPayload length is: %d\n", pkt->pl_size);
	printf("Capture length is: %d\n\n", pkt->pkt_size);
	for (int i = 0; i < pkt->pl_size; i++)
		printf("0x%02x ", pkt->payload[i]);
	printf("\n\n");
}

int packet_parse(const u_char *data, Packet *packet, int len)
{
	int prot;
	uint32_t sip, dip;
	uint16_t sport, dport;
	struct ether_header *ehdr;
	const u_char *pData = data;

	ehdr = (struct ether_header *) pData;

	if (ntohs(ehdr->ether_type) != ETHERTYPE_IP) {
		return 1;
	}

	pData += ETHER_HDR_LEN;

	struct ip *ip_hdr = (struct ip *) pData;

	prot = ip_hdr->ip_p;
	sip = ntohl(ip_hdr->ip_src.s_addr);
	dip = ntohl(ip_hdr->ip_dst.s_addr);
	pData += sizeof(struct ip);

	if (prot == IPPROTO_UDP) {	// UDP
		struct udphdr *uhdr = (struct udphdr *) pData;
		sport = uhdr->source;
		dport = uhdr->dest;
		pData += sizeof(struct udphdr);
	} else if (prot == IPPROTO_TCP) {	// TCP
		struct tcphdr *thdr = (struct tcphdr *) pData;
		sport = thdr->source;
		dport = thdr->dest;
		pData += 4 * thdr->doff;
	} else {
		return 2;
	}

	packet->proto = prot;
	packet->pkt_size = len;
	packet->pl_size = len - (pData - (u_char *)ehdr);
	packet->s_port = ntohs(sport);
	packet->d_port = ntohs(dport);
	packet->s_ip = sip;
	packet->d_ip = dip;
	packet->payload = pData;

	return 0;
}

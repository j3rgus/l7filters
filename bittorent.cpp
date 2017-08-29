#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <pcap.h>
#include <time.h>
#include <errno.h>
#include <sys/time.h>
#include <boost/functional/hash.hpp>
#include <boost/unordered_set.hpp>

#include "network.h"

#define FILTER_STRING	""
#define BUF_LEN			256

/* Bittorent handshake (TCP) */
#define BT_HNDSHK_PATTERN	0x74694213 /* Size (0x13) + "Bit" */
#define BT_HNDSHK_MESSAGE	1

/* TCP tracker */
#define BT_TCP_MIN_SIZE		64
#define BT_TCP_PATTERN_GET	0x20544547 			/* "GET " */
#define BT_TCP_PATTERN_1	0x65636e756f6e6e61 	/* "announce" */
#define BT_TCP_PATTERN_2	0x693f657061726373 	/* "scrape?i" */
#define BT_TCP_TRACKER_MSG	2

/* UDP tracker */
#define BT_UDP_MIN_SIZE		16		/* Request message, smallest message with magic */
#define BT_UDP_ANN_REQ_SIZE	98
#define BT_UDP_CON_MAGIC	0x8019102717040000
#define BT_UDP_ACTION_OFF	0x08	/* Action offset of announce message */
#define BT_UDP_EVENT_OFF	0x50	/* Port offset of annouce message. */
#define BT_UDP_IP_OFF		0x54	/* IP offset of annouce message. */
#define BT_UDP_PORT_OFF		0x60	/* Port offset of annouce message. */
#define BT_UDP_TRACKER_MSG	3
#define BT_UDP_DATA_MSG		4

struct BTStorage {
	uint8_t conn;
	uint32_t ip;
	uint16_t port;
};

boost::unordered_set<BTStorage> btAddrs;

bool operator==(BTStorage const& a, BTStorage const& b)
{
	return ((a.ip == b.ip) && (a.port == b.port) && (a.conn == b.conn));
}

size_t hash_value(BTStorage const& p)
{
	std::size_t seed = 0;

	boost::hash_combine(seed, p.ip);
	boost::hash_combine(seed, p.port);
	boost::hash_combine(seed, p.conn);

	return seed;
}

uint32_t check_for_tcp_msg(Packet *pkt)
{
	uint32_t first_bytes;
	const u_char *packet;
	int len = pkt->pl_size;
	int announce = 0;
	uint32_t msg = 0;

	packet = pkt->payload;

	if (len < BT_TCP_MIN_SIZE)
		return msg;

	first_bytes = *(uint32_t *) packet;

	if (first_bytes == BT_HNDSHK_PATTERN) {
		msg = BT_HNDSHK_MESSAGE;
	}

	if (first_bytes == BT_TCP_PATTERN_GET) {
		/* Set pointer to first character after '/' */
		packet += sizeof(BT_TCP_PATTERN_GET) + 1;

		uint64_t second_bytes = *(uint64_t *) packet;
		switch (second_bytes) {
		case BT_TCP_PATTERN_1:
			announce = 1;
		case BT_TCP_PATTERN_2:
			msg = BT_TCP_TRACKER_MSG;
			break;
		}
	}

	if (announce == 1) {
		printf("Announce ");
		const u_char *match = packet;
		int size = len - (sizeof(BT_TCP_PATTERN_GET) + 6);

		while (size > 0) {
			if (*match == '&') {
				if (!memcmp((void *)(match + 1), "port=", 5)) {
					uint16_t port = atoi((const char *)match+6);
					//if (port != pkt->s_port) {
						BTStorage store = {false, pkt->s_ip, port};
						btAddrs.insert(store);
					//}
					break;
				}
			}
			size--;
			match++;
		}
	}

	return msg;
}

uint32_t check_for_udp_msg(Packet *pkt)
{
	const u_char *packet = pkt->payload;
	int len = pkt->pl_size;
	int msg = 0;

	if (len < BT_UDP_MIN_SIZE)
		return msg;

	uint64_t first_bytes = *(uint64_t *)packet;

	if (first_bytes == BT_UDP_CON_MAGIC) {
		//msg = BT_UDP_TRACKER_MSG;
		return BT_UDP_TRACKER_MSG;
	}

	if (btAddrs.empty() != true) {
		/* Find if there UDP data packet address is stored. */
		BTStorage g_st = {0, pkt->s_ip, pkt->s_port};

		if (btAddrs.find(g_st) != btAddrs.end()) {
			msg = BT_UDP_DATA_MSG;
			btAddrs.erase(g_st);
		}

		if (len < BT_UDP_ANN_REQ_SIZE) {
			return msg;
		}

		/* Find if the connection record is in set */
		BTStorage f_st = {1, pkt->s_ip, pkt->s_port};

		if (btAddrs.find(f_st) != btAddrs.end()) {
			uint32_t action = ntohl(*(uint32_t *) &packet[BT_UDP_ACTION_OFF]);
			uint32_t event = ntohl(*(uint32_t *) &packet[BT_UDP_EVENT_OFF]);

			//printf("Action %0x, event %0x\n", action, event);

			/* event can be 0,1,2,3 and action is 0 for Announce request */
			if ((action == 0) || (event <= 3)) {
				uint32_t ip = ntohl(*(uint32_t *) &packet[BT_UDP_IP_OFF]);
				uint16_t port = ntohs(*(uint16_t *) &packet[BT_UDP_PORT_OFF]);

				BTStorage st = {0, (ip) ? ip : pkt->s_ip, port};

				btAddrs.insert(st);
				msg = BT_UDP_TRACKER_MSG;
			}
		}
	}

	return msg;
}

int main(int argc, char *argv[])
{
	char errbuf[PCAP_ERRBUF_SIZE];
	const u_char *packet;
	struct pcap_pkthdr header;
	pcap_t *pcap;
	bpf_u_int32 netp;
	bpf_u_int32 maskp;
	int ret;
	int counter;

	if (argc < 2) {
		fprintf(stderr, "Need interface as a parameter!\n");
		exit(1);
	}

	ret = pcap_lookupnet(argv[1], &netp, &maskp, errbuf);
	if (ret == -1) {
		fprintf(stderr, "%s\n", errbuf);
		exit(1);
	}

	pcap = pcap_open_live(argv[1], 2000, 0, 0, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "%s\n", errbuf);
		exit(1);
	}

	ret = pcap_datalink(pcap);
	if (ret != DLT_EN10MB) {
		fprintf(stderr, "Interface %s doesn't provide Ethernet headers!\n", argv[1]);
		exit(1);
	}

	counter = 0;

	while (1) {
		Packet pktParsed;

		packet = pcap_next(pcap, &header);
		if (packet == NULL) {
			printf("pcap_next failed to read a packet!\n");
			continue;
		}

		counter++;

		int pkt_ret = packet_parse(packet, &pktParsed, header.caplen);
		if (pkt_ret) {
			continue;
		}

		/*BTStorage st1 = {0, pktParsed.s_ip, pktParsed.s_port};
		BTStorage st2 = {0, pktParsed.d_ip, pktParsed.d_port};
		if ((btAddrs.find(st1) != btAddrs.end()) || (btAddrs.find(st2) != btAddrs.end())) {
			printf("%d Got UDP data message, port %d\n", counter, pktParsed.s_port);
			btAddrs.erase(st1);
			btAddrs.erase(st2);
		}*/

		/* Check for TCP messages (TCP tracker) */
		if (pktParsed.proto == IPPROTO_TCP) {
			int ret = check_for_tcp_msg(&pktParsed);
			if (ret) {
				printf("%d Got TCP message. Type %d \n", counter, ret);
				printf("BTStorage size %lu\n", btAddrs.size());
			}
		}

		/* Check for UDP messages (UDP tracker) */
		if (pktParsed.proto == IPPROTO_UDP) {
			int ret = check_for_udp_msg(&pktParsed);
			if (ret) {
				printf("%d Got UDP message. Type %d \n", counter, ret);
				printf("BTStorage size %lu\n", btAddrs.size());
			}
		}
	}

	pcap_close(pcap);
	return 0;
}

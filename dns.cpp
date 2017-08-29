#include <cstdio>
#include <cstdlib>
#include <signal.h>
#include <cstring>
#include <pcap.h>
#include <time.h>
#include <errno.h>
#include <resolv.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <net/ethernet.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>

#include <vector>
#include <string>
#include <boost/functional/hash.hpp>
#include <boost/unordered_set.hpp>

#include "network.h"

#define FILTER_STRING	""
#define BUF_LEN			256

#define KEYWORDS {"googlevideo"}

struct Address {
	uint8_t ver;
	uint32_t ip[4];
};

/* Keywords to search */
boost::unordered_set<std::string> DNSstrings;

/* Keep addresses for later traffic scan */
boost::unordered_set<Address> dnsAddrs;

inline bool cmp128(const uint32_t *a1, const uint32_t *a2)
{
	uint64_t *a1_tmp = (uint64_t *) a1;
	uint64_t *a2_tmp = (uint64_t *) a2;

	if ((a1_tmp[0] == a2_tmp[0]) && (a1_tmp[1] == a2_tmp[1])) {
		return true;
	}

	return false;
}

bool operator==(Address const& a, Address const& b)
{
	return ((a.ver == b.ver) && cmp128(a.ip, b.ip));
}

size_t hash_value(Address const& p)
{
	std::size_t seed = 0;

	boost::hash_combine(seed, p.ver);
	for (int i = 0; i < 4; i++)
		boost::hash_combine(seed, p.ip[i]);

	return seed;
}

int getIPsFromDNS(ns_msg *nmsg)
{
	ns_rr rr;
	int count;
	int scan = 0;

	count = ns_msg_count(*nmsg, ns_s_qd);

	/* Inspect question(s) for possible keyword match */
	for (int i = 0; (i < count) && !scan; i++) {
		int ret = ns_parserr(nmsg, ns_s_qd, i, &rr);
		if (ret == -1) {
			fprintf(stderr, "ns_parserr: %s", strerror(errno));
			return 1;
		}

		/* Scan only A or AAAA questions. */	
		if ((ns_rr_type(rr) != ns_t_a) && (ns_rr_type(rr) != ns_t_aaaa)) {
			continue;
		}

		const char *dName = ns_rr_name(rr);

		for (auto dnsString : DNSstrings) {
			if (strstr(dName, dnsString.c_str()) != NULL) {
				/* Match found, let's continue to scan answers */
				printf("%s, type %s, class %s\n", dName, p_type(ns_rr_type(rr)), p_class(ns_rr_class(rr)));
				scan = 1;
				break;
			}
		}
	}

	if (!scan) {
		/* No match was found - nothing to scan anymore. */
		return 1;
	}

	count = ns_msg_count(*nmsg, ns_s_an);

	/* Scan answers for IP addresses */
	for (int i = 0; i < count; i++) {
		int ret = ns_parserr(nmsg, ns_s_an, i, &rr);
		if (ret == -1) {
			fprintf(stderr, "ns_parserr: %s", strerror(errno));
			return 1;
		}

		const u_char *data = ns_rr_rdata(rr);
		Address addr;

		/* If answer is A, save the IP address */
		if (ns_rr_type(rr) == ns_t_a) {
			addr.ver = 4;
			addr.ip[0] = ntohl(*(uint32_t *) data);
			addr.ip[1] = addr.ip[2] = addr.ip[3] = 0;
			dnsAddrs.insert(addr);
			printf("IPv4 address added into internal storage\n");
		}

		/* If answer is AAAA, save the IPV6 address */
		if (ns_rr_type(rr) == ns_t_aaaa) {
			addr.ver = 6;
			addr.ip[0] = ntohl(*(uint32_t *) data);
			addr.ip[1] = ntohl(*(uint32_t *) &data[4]);
			addr.ip[2] = ntohl(*(uint32_t *) &data[8]);
			addr.ip[3] = ntohl(*(uint32_t *) &data[12]);
			dnsAddrs.insert(addr);
			char buf[64];
			printf("IPv6 address %s added into internal storage\n", inet_ntop(AF_INET6, (char *) addr.ip, buf, 63));
		}

		/* If answer is CNAME, save the name into vector */
		if (ns_rr_type(rr) == ns_t_cname) {
			char cname[256];
			int ret = ns_name_uncompress(ns_msg_base(*nmsg), ns_msg_end(*nmsg), data, cname, 255);
			if (ret == -1) {
				continue;
			}

			if (DNSstrings.insert(cname).second) {
				printf("Name %s was added to set.\n", cname);
			}
		}

		printf("Size of set is %lu\n", dnsAddrs.size());
		for (auto address : dnsAddrs) {
			char buf[64];
			printf("ver: %d, IP: %s\n", address.ver, (address.ver == 4) ? inet_ntop(AF_INET, (char *) address.ip, buf, 63) : inet_ntop(AF_INET6, (char *) address.ip, buf, 63));
		}
	}

	return 0;
}

int main(int argc, char *argv[])
{
	char errbuf[PCAP_ERRBUF_SIZE];
	const u_char *packet;
	pcap_t *pcap;
	struct bpf_program fp;
	struct pcap_pkthdr header;
	bpf_u_int32 netp;
	bpf_u_int32 maskp;
	int ret;

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

	ret = pcap_compile(pcap, &fp, FILTER_STRING, 0, netp);
	if (ret == -1) {
		pcap_perror(pcap, (char *)"pcap_compile");
		exit(1);
	}

	ret = pcap_setfilter(pcap, &fp);
	if (ret == -1) {
		pcap_perror(pcap, (char *)"pcap_setfilter");
		exit(1);
	}

	DNSstrings = KEYWORDS;

	while (1) {
		Packet pktParsed;

		packet = pcap_next(pcap, &header);
		//printf("Packet captured at %s", ctime((time_t *) &header.ts.tv_sec));

		int pkt_ret = packet_parse(packet, &pktParsed, header.caplen);
		if (pkt_ret) {
			continue;
		}

		/* Compare addresses with stored addresses */
		if (!dnsAddrs.empty()) {
			Address addrSrc, addrDst;
			addrSrc.ver = addrDst.ver = 4;
			addrSrc.ip[0] = pktParsed.s_ip;
			addrDst.ip[0] = pktParsed.d_ip;
			addrSrc.ip[1] = addrSrc.ip[2] = addrSrc.ip[3] = 0;
			addrDst.ip[1] = addrDst.ip[2] = addrDst.ip[3] = 0;

			if ((dnsAddrs.find(addrSrc) != dnsAddrs.end()) || (dnsAddrs.find(addrDst) != dnsAddrs.end())) {
				//printf("Packet found\n");
			}
		}

		if ((pktParsed.proto == IPPROTO_UDP) && ((pktParsed.s_port == 53) || (pktParsed.d_port == 53))) {
			ns_msg nmsg;

			errno = 0;
			ret = ns_initparse(pktParsed.payload, pktParsed.pl_size, &nmsg);
			if (ret == -1) {
				fprintf(stderr, "ns_initparse: %s\n", strerror(errno));
				continue;
			}

			/* Only response is important as it carries IP addresses */
			int code = ns_msg_getflag(nmsg, ns_f_qr);

			printf("Code: %d\n", code);
			if (code) {
				getIPsFromDNS(&nmsg);
			}
		}
	}

	pcap_close(pcap);
	return 0;
}

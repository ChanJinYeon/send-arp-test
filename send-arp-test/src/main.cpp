#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
#include "myaddr.h"

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
	printf("syntax: send-arp-test <interface>\n");
	printf("sample: send-arp-test wlan0\n");
}

int main(int argc, char* argv[]) {
	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}

	char myMac[18];
	char myIp[16];

	getMacAddress(myMac, dev);
	getIpAddress(myIp, 16, dev);

	printf("%s\n", myMac);
	printf("%s\n", myIp);

/**************************** 이상 무 *******************************/

	for (int i = 2; i < argc-1; i += 2) {
	
		EthArpPacket packet;
		Mac senderMac;

		// 첫 번째
		packet.eth_.dmac_ = Mac("FF:FF:FF:FF:FF:FF");
		packet.eth_.smac_ = Mac(myMac);
		packet.eth_.type_ = htons(EthHdr::Arp);

		packet.arp_.hrd_ = htons(ArpHdr::ETHER);
		packet.arp_.pro_ = htons(EthHdr::Ip4);
		packet.arp_.hln_ = Mac::SIZE;
		packet.arp_.pln_ = Ip::SIZE;
		packet.arp_.op_ = htons(ArpHdr::Request);
		packet.arp_.smac_ = Mac(myMac);
		packet.arp_.sip_ = htonl(Ip(myIp));
		packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
		packet.arp_.tip_ = htonl(Ip(argv[i]));

		int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
		if (res != 0) {
			fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
		}
		
		/********************* 패킷 받기 ************************/

		while (true) {
			struct pcap_pkthdr* header;
			const u_char* pack;
			int res = pcap_next_ex(handle, &header, &pack);
			if (res == 0) continue;
			if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
				printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
				break;
			}

			struct EthArpPacket *ARPP = (struct EthArpPacket *)pack;
			if(ntohs(ARPP->eth_.type_) == 0x0806) {
				senderMac = ARPP->arp_.smac_;
				break;
			}

		}

		/********************************************************/

		// 두 번째
		EthArpPacket packet2;

		packet2.eth_.dmac_ = senderMac;
		packet2.eth_.smac_ = Mac(myMac);
		packet2.eth_.type_ = htons(EthHdr::Arp);

		packet2.arp_.hrd_ = htons(ArpHdr::ETHER);
		packet2.arp_.pro_ = htons(EthHdr::Ip4);
		packet2.arp_.hln_ = Mac::SIZE;
		packet2.arp_.pln_ = Ip::SIZE;
		packet2.arp_.op_ = htons(ArpHdr::Request);
		packet2.arp_.smac_ = Mac(myMac);
		packet2.arp_.sip_ = htonl(Ip(argv[i+1]));
		packet2.arp_.tmac_ = senderMac;
		packet2.arp_.tip_ = htonl(Ip(argv[i]));

		res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet2), sizeof(EthArpPacket));
		if (res != 0) {
			fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
		}
	}

	pcap_close(handle);
}

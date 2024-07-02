#include "util.h"

bool getHostMacAddress(const char *interfaceName, Mac *macAddress)
{
	int sockfd;
	struct ifreq ifr;

	// Create UDP socket
	sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sockfd < 0)
	{
		printf("[ERR] socket error\n");
		return false;
	}

	// Set interface name
	strncpy(ifr.ifr_name, interfaceName, IFNAMSIZ - 1);
	ifr.ifr_name[IFNAMSIZ - 1] = '\0';

	// Get mac addr
	if (ioctl(sockfd, SIOCGIFHWADDR, &ifr) == -1)
	{
		printf("[ERR] ioctl error\n");
		close(sockfd);
		return -1;
	}
	*macAddress = (uint8_t *)(ifr.ifr_hwaddr.sa_data);

	printf("[*] attackerMac  : %s\n", std::string(*macAddress).c_str());
	close(sockfd);
	return true;
}

bool getHostIpAddress(const char *interfaceName, Ip *ipAddress)
{
	int sockfd;
	struct ifreq ifr;

	// Create UDP socket
	sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sockfd < 0)
	{
		printf("[ERR] socket error\n");
		return false;
	}

	// Set interface name
	strncpy(ifr.ifr_name, interfaceName, IFNAMSIZ - 1);
	ifr.ifr_name[IFNAMSIZ - 1] = '\0';

	// Get Ip addr
	if (ioctl(sockfd, SIOCGIFADDR, &ifr) == -1)
	{
		printf("[ERR] ioctl error\n");
		close(sockfd);
		return false;
	}
	*ipAddress = Ip(inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr));
	printf("[*] attackerIp   : %s\n", std::string(*ipAddress).c_str());

	close(sockfd);
	return true;
}

void getHostInfo(const char *interfaceName, Ip *ipAddress, Mac *macAddress)
{
	// Logging
	printf("\n----------------------------------------\n");
	printf("[*] get host info..");
	printf("\n----------------------------------------\n");
	if (!getHostIpAddress(interfaceName, ipAddress))
		printf("[*] failed to get Host Ip\n");
	if (!getHostMacAddress(interfaceName, macAddress))
		printf("[*] failed to get Host Mac\n");
}

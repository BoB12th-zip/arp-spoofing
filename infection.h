#pragma pack(push, 1)
struct EthArpPacket final
{
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

#pragma pack(push, 1)
struct IpPacket final
{
	EthHdr eth_;
	IpHdr ip_;
};
#pragma pack(pop)
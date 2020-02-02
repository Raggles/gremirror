/*************************************************************************/
/* Based on GRE Tunnel example from NT Kernel Resources                  */
/*************************************************************************/

#include "stdafx.h"


// Packet filter definitions from DDK
#define NDIS_PACKET_TYPE_DIRECTED				0x00000001
#define NDIS_PACKET_TYPE_MULTICAST				0x00000002
#define NDIS_PACKET_TYPE_ALL_MULTICAST			0x00000004
#define NDIS_PACKET_TYPE_BROADCAST				0x00000008
#define NDIS_PACKET_TYPE_SOURCE_ROUTING			0x00000010
#define NDIS_PACKET_TYPE_PROMISCUOUS			0x00000020
#define NDIS_PACKET_TYPE_SMT					0x00000040
#define NDIS_PACKET_TYPE_ALL_LOCAL				0x00000080
#define NDIS_PACKET_TYPE_GROUP					0x00001000
#define NDIS_PACKET_TYPE_ALL_FUNCTIONAL			0x00002000
#define NDIS_PACKET_TYPE_FUNCTIONAL				0x00004000
#define NDIS_PACKET_TYPE_MAC_FRAME				0x00008000

#define VERBOSE false

TCP_AdapterList		AdList;
DWORD				iListenIndex;
DWORD				iSendIndex;
CNdisApi			api;
ETH_REQUEST			Request;
INTERMEDIATE_BUFFER PacketBuffer;
HANDLE				hListenEvent;
HANDLE				hSendEvent;
DWORD				dwFilter = 0;

//
// Function recalculates IP checksum
//
VOID RecalculateIPChecksum(iphdr_ptr pIpHeader)
{
	unsigned short word16;
	unsigned int sum = 0;
	unsigned int i = 0;
	PUCHAR buff;

	// Initialize checksum to zero
	pIpHeader->ip_sum = 0;
	buff = (PUCHAR)pIpHeader;

	// Calculate IP header checksum
	for (i = 0; i < pIpHeader->ip_hl * sizeof(DWORD); i = i + 2)
	{
		word16 = ((buff[i] << 8) & 0xFF00) + (buff[i + 1] & 0xFF);
		sum = sum + word16;
	}

	// keep only the last 16 bits of the 32 bit calculated sum and add the carries
	while (sum >> 16)
		sum = (sum & 0xFFFF) + (sum >> 16);

	// Take the one's complement of sum
	sum = ~sum;

	pIpHeader->ip_sum = htons((unsigned short)sum);
}

void ReleaseInterface(DWORD iIndex, HANDLE hEvent)
{
	
}

//
//Releases packets in the adapter queue and stops listening the interface
//
void ReleaseInterface()
{
	// Restore old packet filter
	api.SetHwPacketFilter(AdList.m_nAdapterHandle[iListenIndex], dwFilter);

	ADAPTER_MODE Mode;

	Mode.dwFlags = 0;
	Mode.hAdapterHandle = (HANDLE)AdList.m_nAdapterHandle[iListenIndex];

	// Set NULL event to release previously set event object
	api.SetPacketEvent(AdList.m_nAdapterHandle[iListenIndex], NULL);

	// Close Event
	if (hListenEvent)
		CloseHandle(hListenEvent);

	// Set default adapter mode
	api.SetAdapterMode(&Mode);

	// Empty adapter packets queue
	api.FlushAdapterPacketQueue(AdList.m_nAdapterHandle[iListenIndex]);
}

//
//Print program help
//
void usage(char *pname)
{
	CNdisApi			api;
	TCP_AdapterList		AdList;
	OSVERSIONINFO		verInfo;
	char				szFriendlyName[MAX_PATH * 4];
	ADAPTER_MODE		Mode;

	printf("Usage: %s dst-ip src-ip listen-index send-index \n", pname);
	printf("\t dst-ip \tdestination IP address\n");
	printf("\t src-ip \tsource IP address\n");
	printf("\t listen-index \tadapter index to listen on\n");
	printf("\t send-index \tadapter index to send on\n\n");



	verInfo.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);
	GetVersionEx(&verInfo);

	DWORD dwMTUDec = api.GetMTUDecrement();
	DWORD dwAdapterStartupMode = api.GetAdaptersStartupMode();

	if (api.IsDriverLoaded())
	{
		printf("The following network interfaces are available to MSTCP:\n");
		api.GetTcpipBoundAdaptersInfo(&AdList);

		for (UINT i = 0; i < AdList.m_nAdapterCount; ++i)
		{
			if (verInfo.dwPlatformId == VER_PLATFORM_WIN32_NT)
			{
				if (verInfo.dwMajorVersion > 4)
				{
					// Windows 2000 or XP
					CNdisApi::ConvertWindows2000AdapterName((const char*)AdList.m_szAdapterNameList[i], szFriendlyName, MAX_PATH * 4);
				}
				else if (verInfo.dwMajorVersion == 4)
				{
					// Windows NT 4.0	
					CNdisApi::ConvertWindowsNTAdapterName((const char*)AdList.m_szAdapterNameList[i], szFriendlyName, MAX_PATH * 4);
				}
			}
			else
			{
				// Windows 9x/ME
				CNdisApi::ConvertWindows9xAdapterName((const char*)AdList.m_szAdapterNameList[i], szFriendlyName, MAX_PATH * 4);
			}

			printf("%d) %s.\n", i + 1, szFriendlyName);
			printf("\tInternal Name:\t %s\n", AdList.m_szAdapterNameList[i]);

			printf(
				"\tCurrent MAC:\t %.2X%.2X%.2X%.2X%.2X%.2X\n",
				AdList.m_czCurrentAddress[i][0],
				AdList.m_czCurrentAddress[i][1],
				AdList.m_czCurrentAddress[i][2],
				AdList.m_czCurrentAddress[i][3],
				AdList.m_czCurrentAddress[i][4],
				AdList.m_czCurrentAddress[i][5]
			);
			printf("\tMedium:\t 0x%.8X\n", AdList.m_nAdapterMediumList[i]);
			printf("\tCurrent MTU:\t %d\n", AdList.m_usMTU[i]);

			RtlZeroMemory(&Mode, sizeof(ADAPTER_MODE));
			Mode.hAdapterHandle = AdList.m_nAdapterHandle[i];
			if (api.GetAdapterMode(&Mode))
				printf("\tCurrent adapter mode = 0x%X\n", Mode.dwFlags);

			DWORD dwAdapterHwFilter = 0;
			if (api.GetHwPacketFilter(AdList.m_nAdapterHandle[i], &dwAdapterHwFilter))
				printf("\tCurrent adapter hardware filter = 0x%X\n", dwAdapterHwFilter);

			if ((CNdisApi::IsNdiswanIp((LPCSTR)AdList.m_szAdapterNameList[i])) ||
				(CNdisApi::IsNdiswanIpv6((LPCSTR)AdList.m_szAdapterNameList[i])))
			{
				RAS_LINKS RasLinks;
				if (api.GetRasLinks(AdList.m_nAdapterHandle[i], &RasLinks))
				{
					printf("Number of active WAN links: %d \n", RasLinks.nNumberOfLinks);

					for (unsigned k = 0; k < RasLinks.nNumberOfLinks; ++k)
					{
						printf("\t%d) LinkSpeed = %d MTU = %d \n", k, RasLinks.RasLinks[k].LinkSpeed, RasLinks.RasLinks[k].MaximumTotalSize);
						printf(
							"\t\tLocal MAC:\t %.2X%.2X%.2X%.2X%.2X%.2X\n",
							RasLinks.RasLinks[k].LocalAddress[0],
							RasLinks.RasLinks[k].LocalAddress[1],
							RasLinks.RasLinks[k].LocalAddress[2],
							RasLinks.RasLinks[k].LocalAddress[3],
							RasLinks.RasLinks[k].LocalAddress[4],
							RasLinks.RasLinks[k].LocalAddress[5]
						);

						printf(
							"\t\tRemote MAC:\t %.2X%.2X%.2X%.2X%.2X%.2X\n",
							RasLinks.RasLinks[k].RemoteAddress[0],
							RasLinks.RasLinks[k].RemoteAddress[1],
							RasLinks.RasLinks[k].RemoteAddress[2],
							RasLinks.RasLinks[k].RemoteAddress[3],
							RasLinks.RasLinks[k].RemoteAddress[4],
							RasLinks.RasLinks[k].RemoteAddress[5]
						);

						if (CNdisApi::IsNdiswanIp((LPCSTR)AdList.m_szAdapterNameList[i]))
						{
							// IP v.4
							if (verInfo.dwMajorVersion == 4)
							{
								printf(
									"\t\tIP address:\t %.3d.%.3d.%.3d.%.3d\n",
									RasLinks.RasLinks[k].ProtocolBuffer[4],
									RasLinks.RasLinks[k].ProtocolBuffer[5],
									RasLinks.RasLinks[k].ProtocolBuffer[6],
									RasLinks.RasLinks[k].ProtocolBuffer[7]
								);

							}
							else if (verInfo.dwMajorVersion < 6)
							{
								printf(
									"\t\tIP address:\t %.3d.%.3d.%.3d.%.3d mask %.3d.%.3d.%.3d.%.3d\n",
									RasLinks.RasLinks[k].ProtocolBuffer[8],
									RasLinks.RasLinks[k].ProtocolBuffer[9],
									RasLinks.RasLinks[k].ProtocolBuffer[10],
									RasLinks.RasLinks[k].ProtocolBuffer[11],
									RasLinks.RasLinks[k].ProtocolBuffer[4],
									RasLinks.RasLinks[k].ProtocolBuffer[5],
									RasLinks.RasLinks[k].ProtocolBuffer[6],
									RasLinks.RasLinks[k].ProtocolBuffer[7]
								);
							}
							else
							{
								// Windows Vista
								printf(
									"\t\tIP address:\t %.3d.%.3d.%.3d.%.3d mask %.3d.%.3d.%.3d.%.3d\n",
									RasLinks.RasLinks[k].ProtocolBuffer[584],
									RasLinks.RasLinks[k].ProtocolBuffer[585],
									RasLinks.RasLinks[k].ProtocolBuffer[586],
									RasLinks.RasLinks[k].ProtocolBuffer[587],
									RasLinks.RasLinks[k].ProtocolBuffer[588],
									RasLinks.RasLinks[k].ProtocolBuffer[589],
									RasLinks.RasLinks[k].ProtocolBuffer[590],
									RasLinks.RasLinks[k].ProtocolBuffer[591]
								);
							}
						}
						else
						{
							// IP v.6
							if (verInfo.dwMajorVersion > 5)
							{
								printf(
									"\t\tIPv6 address (without prefix):\t %.2X%.2X:%.2X%.2X:%.2X%.2X:%.2X%.2X\n",
									RasLinks.RasLinks[k].ProtocolBuffer[588],
									RasLinks.RasLinks[k].ProtocolBuffer[589],
									RasLinks.RasLinks[k].ProtocolBuffer[590],
									RasLinks.RasLinks[k].ProtocolBuffer[591],
									RasLinks.RasLinks[k].ProtocolBuffer[592],
									RasLinks.RasLinks[k].ProtocolBuffer[593],
									RasLinks.RasLinks[k].ProtocolBuffer[594],
									RasLinks.RasLinks[k].ProtocolBuffer[595]
								);
							}
						}

					}
				}
				else
				{
					printf("Failed to query active WAN links information.\n");
				}
			}

		}
		printf("\nCurrent system wide MTU decrement = %d\n", dwMTUDec);
		printf("\nDefault adapter startup mode = 0x%X", dwAdapterStartupMode);
	}
	else
	{
		printf("Helper driver failed to load or was not installed.\n");
	}
}

int main(int argc, char* argv[])
{
	UINT				counter = 0;
	ether_header*		pEthHeader = NULL;
	iphdr*				pIpHeader = NULL;
	ipgre_hdr*			pIpGreHeader = NULL;
	tcphdr_ptr			pTcpHdr = NULL;
	udphdr_ptr			pUdpHdr = NULL;
	bool				blockPacket = false;
	DWORD dwRetVal;
	ULONG MacAddr[2];       /* for 6-byte hardware addresses */
	ULONG PhysAddrLen = 6;  /* default to length of six bytes */

	char *DestIpString = NULL;
	char *SrcIpString = NULL;
	in_addr SrcIp;
	in_addr DestIp;
	BYTE *bPhysAddr;
	unsigned int i;

	if (argc > 4) {
		DestIpString = argv[1];
		SrcIpString = argv[2];
		if (InetPton(AF_INET, DestIpString, &DestIp) != 1)
		{
			printf("Couldn't parse destination ip address\n");
		}
		if (InetPton(AF_INET, SrcIpString, &SrcIp) != 1)
		{
			printf("Couldn't parse source ip address\n");
		}
		iListenIndex = atoi(argv[3]) - 1;
		iSendIndex = atoi(argv[4]) - 1;

	}
	else {
		usage(argv[0]);
		return 0;
	}
	memset(&MacAddr, 0xff, sizeof(MacAddr));

	printf("Sending ARP request for IP address: %s\n", DestIpString);

	dwRetVal = SendARP(DestIp.S_un.S_addr, SrcIp.S_un.S_addr, &MacAddr, &PhysAddrLen);

	if (dwRetVal == NO_ERROR) {
		bPhysAddr = (BYTE *)& MacAddr;
		if (PhysAddrLen) {
			for (i = 0; i < (int)PhysAddrLen; i++) {
				if (i == (PhysAddrLen - 1))
					printf("%.2X\n", (int)bPhysAddr[i]);
				else
					printf("%.2X-", (int)bPhysAddr[i]);
			}
		}
		else {
			printf("Warning: SendArp completed successfully, but returned length=0\n");
			return 0;
		}
	}
	else {
		printf("Error: SendArp failed with error: %d", dwRetVal);
		switch (dwRetVal) {
		case ERROR_GEN_FAILURE:
			printf(" (ERROR_GEN_FAILURE)\n");
			break;
		case ERROR_INVALID_PARAMETER:
			printf(" (ERROR_INVALID_PARAMETER)\n");
			break;
		case ERROR_INVALID_USER_BUFFER:
			printf(" (ERROR_INVALID_USER_BUFFER)\n");
			break;
		case ERROR_BAD_NET_NAME:
			printf(" (ERROR_GEN_FAILURE)\n");
			break;
		case ERROR_BUFFER_OVERFLOW:
			printf(" (ERROR_BUFFER_OVERFLOW)\n");
			break;
		case ERROR_NOT_FOUND:
			printf(" (ERROR_NOT_FOUND)\n");
			break;
		default:
			printf("\n");
			break;
		}
		return 0;
	}


	if (!api.IsDriverLoaded())
	{
		printf("Driver not installed on this system of failed to load.\n");
		return 0;
	}

	api.GetTcpipBoundAdaptersInfo(&AdList);

	if (iListenIndex + 1 > AdList.m_nAdapterCount)
	{
		printf("There is no network interface with such iListenIndex on this system.\n");
		return 0;
	}
	if (iSendIndex + 1 > AdList.m_nAdapterCount)
	{
		printf("There is no network interface with such iSendIndex on this system.\n");
		return 0;
	}
	DWORD dwMTUDec = api.GetMTUDecrement();

	if (dwMTUDec != sizeof(ipgre_hdr))
	{
		api.SetMTUDecrement(sizeof(ipgre_hdr));
		printf("Incorrect MTU decrement was set for the system. New MTU decrement is %d bytes. Please reboot the system for the changes to take the effect.\n", sizeof(ipgre_hdr));
		return 0;
	}

	ADAPTER_MODE Mode;

	// Read current packet filter and set NDIS_PACKET_TYPE_PROMISCUOUS 
	HANDLE hAdapter = AdList.m_nAdapterHandle[iListenIndex];

	if (!api.GetHwPacketFilter(hAdapter, &dwFilter))
		printf("Failed to get current packet filter from the network interface.\n");

	if (!api.SetHwPacketFilter(hAdapter, NDIS_PACKET_TYPE_PROMISCUOUS))
		printf("Failed to set promiscuous mode for the network interface.\n");

	// If promiscuous mode specified then set TCP/IP direct filter to prevent TCP/IP
	// from receiving non-directed packets and set block loopback filter to prevent packet loop
	Mode.dwFlags = MSTCP_FLAG_RECV_LISTEN | MSTCP_FLAG_FILTER_DIRECT | MSTCP_FLAG_LOOPBACK_BLOCK;
	Mode.hAdapterHandle = (HANDLE)AdList.m_nAdapterHandle[iListenIndex];
	api.SetAdapterMode(&Mode);

	// Create notification event
	hListenEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
	
	// Set event for helper driver
	if ((!hListenEvent) || (!api.SetPacketEvent((HANDLE)AdList.m_nAdapterHandle[iListenIndex], hListenEvent)))
	{
		printf("Failed to create notification event or set it for driver.\n");
		return 0;
	}

	atexit(ReleaseInterface);

	// Initialize Request
	ZeroMemory(&Request, sizeof(ETH_REQUEST));
	ZeroMemory(&PacketBuffer, sizeof(INTERMEDIATE_BUFFER));
	Request.EthPacket.Buffer = &PacketBuffer;
	Request.hAdapterHandle = (HANDLE)AdList.m_nAdapterHandle[iListenIndex];

	while (1)
	{
		WaitForSingleObject(hListenEvent, INFINITE);

		while (api.ReadPacket(&Request))
		{
			//uncomment if want to send to adapter for wireshark etc
			//api.SendPacketToAdapter(&Request);

			pEthHeader = (ether_header*)PacketBuffer.m_IBuffer;
			if ((ntohs(pEthHeader->h_proto) == ETH_P_IP) && (PacketBuffer.m_dwDeviceFlags == PACKET_FLAG_ON_RECEIVE))
			{
				if (PacketBuffer.m_Length <= (MAX_ETHER_FRAME - sizeof(ipgre_hdr)))
				{
					// We have got enough space in the packet to attach GRE header
					// Get IP header pointer
					pIpHeader = (iphdr*)(pEthHeader + 1);

					if (pIpHeader->ip_p == IPPROTO_TCP || pIpHeader->ip_p == IPPROTO_UDP)
					{
						counter++;
						if (VERBOSE)
						{
							printf("\t %d Inbound TCP\\UDP pakcet will be GRE tunneled \n", counter);
						}
						// Move IP packet body by sizeof(ipgre_hdr) bytes
						// Previous IP header stays unchanged
						memmove(((unsigned char*)pIpHeader) + sizeof(ipgre_hdr), pIpHeader, PacketBuffer.m_Length - sizeof(ether_header));

						// Change the length field of the new IP header
						pIpGreHeader = (ipgre_hdr*)pIpHeader;

						//update the source and destination MAC addresses
						pEthHeader->h_source[0] = AdList.m_czCurrentAddress[iSendIndex][0];
						pEthHeader->h_source[1] = AdList.m_czCurrentAddress[iSendIndex][1];
						pEthHeader->h_source[2] = AdList.m_czCurrentAddress[iSendIndex][2];
						pEthHeader->h_source[3] = AdList.m_czCurrentAddress[iSendIndex][3];
						pEthHeader->h_source[4] = AdList.m_czCurrentAddress[iSendIndex][4];
						pEthHeader->h_source[5] = AdList.m_czCurrentAddress[iSendIndex][5];

						pEthHeader->h_dest[0] = bPhysAddr[0];
						pEthHeader->h_dest[1] = bPhysAddr[1];
						pEthHeader->h_dest[2] = bPhysAddr[2];
						pEthHeader->h_dest[3] = bPhysAddr[3];
						pEthHeader->h_dest[4] = bPhysAddr[4];
						pEthHeader->h_dest[5] = bPhysAddr[5];

						//update the source and destination IP addresses
						pIpGreHeader->ip_header.ip_dst.S_un.S_un_b.s_b1 = DestIp.S_un.S_un_b.s_b1;
						pIpGreHeader->ip_header.ip_dst.S_un.S_un_b.s_b2 = DestIp.S_un.S_un_b.s_b2;
						pIpGreHeader->ip_header.ip_dst.S_un.S_un_b.s_b3 = DestIp.S_un.S_un_b.s_b3;
						pIpGreHeader->ip_header.ip_dst.S_un.S_un_b.s_b4 = DestIp.S_un.S_un_b.s_b4;

						pIpGreHeader->ip_header.ip_src.S_un.S_un_b.s_b1 = SrcIp.S_un.S_un_b.s_b1;
						pIpGreHeader->ip_header.ip_src.S_un.S_un_b.s_b2 = SrcIp.S_un.S_un_b.s_b2;
						pIpGreHeader->ip_header.ip_src.S_un.S_un_b.s_b3 = SrcIp.S_un.S_un_b.s_b3;
						pIpGreHeader->ip_header.ip_src.S_un.S_un_b.s_b4 = SrcIp.S_un.S_un_b.s_b4;

						pIpHeader->ip_len = ntohs(ntohs(pIpHeader->ip_len) + sizeof(ipgre_hdr));

						// Set next protocol to GRE
						pIpHeader->ip_p = IPPROTO_GRE;

						// Recalculate IP checksum
						RecalculateIPChecksum(pIpHeader);

						// Initialize GRE header
						pIpGreHeader->gre_header.flags = 0;
						pIpGreHeader->gre_header.protocol = ntohs(ETH_P_IP);

						// Adjust packet length 
						PacketBuffer.m_Length += sizeof(ipgre_hdr);

						Request.hAdapterHandle = (HANDLE)AdList.m_nAdapterHandle[iSendIndex];
						// Place packet on the network interface
						api.SendPacketToAdapter(&Request);
					}
				}
				else
				{
					printf("\t Packet length = %d bytes. Not enough space to attach GRE header. Check MTU decrement. \n", PacketBuffer.m_Length);
				}
			}
			Request.hAdapterHandle = (HANDLE)AdList.m_nAdapterHandle[iListenIndex];
		}
		ResetEvent(hListenEvent);
	}
	return 0;
}


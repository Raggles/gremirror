/*************************************************************************/
/* Based on GRE Tunnel example from NT Kernel Resources                  */
/*************************************************************************/

#include "stdafx.h"
TCP_AdapterList		AdList;
DWORD				iIndex;
CNdisApi			api;
ETH_REQUEST			Request;
INTERMEDIATE_BUFFER PacketBuffer;
HANDLE				hEvent;

USHORT ntohs( USHORT netshort )
{
	PUCHAR	pBuffer;
	USHORT	nResult;

	nResult = 0;
	pBuffer = (PUCHAR )&netshort;

	nResult = ( (pBuffer[ 0 ] << 8) & 0xFF00 )
		| ( pBuffer[ 1 ] & 0x00FF );

	return( nResult );
}

#define htons ntohs
#define VERBOSE false

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

void ReleaseInterface()
{
	// This function releases packets in the adapter queue and stops listening the interface
	ADAPTER_MODE Mode;

	Mode.dwFlags = 0;
	Mode.hAdapterHandle = (HANDLE)AdList.m_nAdapterHandle[iIndex];

	// Set NULL event to release previously set event object
	api.SetPacketEvent(AdList.m_nAdapterHandle[iIndex], NULL);

	// Close Event
	if (hEvent)
		CloseHandle ( hEvent );

	// Set default adapter mode
	api.SetAdapterMode(&Mode);

	// Empty adapter packets queue
	api.FlushAdapterPacketQueue (AdList.m_nAdapterHandle[iIndex]);
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

	printf("Usage: %s index \n", pname);
	printf("\t index \tadapter index to use on\n");



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
		printf("Helper driver failed to load or was not installed.\n");

	exit(1);
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

	if (argc < 2)
	{
		usage(argv[0]);
		return 0;
	}

	iIndex = atoi(argv[1]) - 1;

	if(!api.IsDriverLoaded())
	{
		printf ("Driver not installed on this system of failed to load.\n");
		return 0;
	}
	
	api.GetTcpipBoundAdaptersInfo ( &AdList );

	if ( iIndex + 1 > AdList.m_nAdapterCount )
	{
		printf("There is no network interface with such index on this system.\n");
		return 0;
	}
	
	ADAPTER_MODE Mode;

	Mode.dwFlags = MSTCP_FLAG_RECV_TUNNEL;
	Mode.hAdapterHandle = (HANDLE)AdList.m_nAdapterHandle[iIndex];

	// Create notification event
	hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);

	// Set event for helper driver
	if ((!hEvent)||(!api.SetPacketEvent((HANDLE)AdList.m_nAdapterHandle[iIndex], hEvent)))
	{
		printf ("Failed to create notification event or set it for driver.\n");
		return 0;
	}

	atexit (ReleaseInterface);
	
	// Initialize Request
	ZeroMemory ( &Request, sizeof(ETH_REQUEST) );
	ZeroMemory ( &PacketBuffer, sizeof(INTERMEDIATE_BUFFER) );
	Request.EthPacket.Buffer = &PacketBuffer;
	Request.hAdapterHandle = (HANDLE)AdList.m_nAdapterHandle[iIndex];
		
	api.SetAdapterMode(&Mode);

	while (1)
	{
		WaitForSingleObject ( hEvent, INFINITE );
		while (api.ReadPacket(&Request))
		{

			pEthHeader = (ether_header*)PacketBuffer.m_IBuffer;

			if ((ntohs(pEthHeader->h_proto) == ETH_P_IP) && (PacketBuffer.m_dwDeviceFlags == PACKET_FLAG_ON_RECEIVE))
			{
				// Get IP header pointer
				pIpHeader = (iphdr*)(pEthHeader + 1);

				if (pIpHeader->ip_p == IPPROTO_GRE)
				{
					if (VERBOSE)
					{
						counter++;
						printf("\t %d Incoming IP packet with GRE header \n", counter);
					}

					pIpGreHeader = (ipgre_hdr*)pIpHeader;

					// We process only simple GRE tunnels
					if (pIpGreHeader->gre_header.flags == 0)
					{
						// Remove GRE header and adjust packet length
						memmove(pIpHeader, ((unsigned char*)pIpHeader) + sizeof(ipgre_hdr), PacketBuffer.m_Length - sizeof(ether_header) - sizeof(ipgre_hdr));
						PacketBuffer.m_Length -= sizeof(ipgre_hdr);
					}
					else
					{
						if (VERBOSE)
						{
							printf("\tThis is not SIMPLE GRE packet, skip it . \n");
						}
					}
				}
			}

			// Indicate packet to MSTCP
			if (PacketBuffer.m_dwDeviceFlags == PACKET_FLAG_ON_RECEIVE)
			{
				if (VERBOSE)
				{
					printf("\t %d Forwarding Packet \n", counter);
				}
				// Indicate packet to MSTCP
				api.SendPacketToMstcp(&Request);
			}
		}
		ResetEvent(hEvent);
	}
	return 0;
}

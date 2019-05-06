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
		printf ("Command line syntax:\n\tgrestrip.exe index num\n\tindex - network interface index.\n\tYou can use ListAdapters to determine correct index.\n");
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

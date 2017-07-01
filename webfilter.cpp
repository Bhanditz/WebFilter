#define _CRT_SECURE_NO_WARNINGS
#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "WinDivert.lib")

/*
 * DESCRIPTION:
 * This is a simple web (HTTP) filter using WinDivert.
 *
 * It works by intercepting outbound HTTP GET/POST requests and matching
 * the URL against a blacklist. If the URL is matched, we hijack the TCP
 * connection, reseting the connection at the server end, and sending a
 * blockpage to the browser.
 */

#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>

#include "windivert.h"

/*
 * Pre-fabricated packets.
 */
typedef struct
{
	WINDIVERT_IPHDR  ip;
	WINDIVERT_TCPHDR tcp;
} PACKET, *PPACKET;
typedef struct
{
	PACKET header;
	UINT8  data[1]; //dummy
} DATAPACKET, *PDATAPACKET;

/*
 *	WinDivert HANDLE
 */
static volatile HANDLE g_WDHandle = INVALID_HANDLE_VALUE;

/*
 *	ctrl+c handler
 */
void ctrlc_handler(int sig)
{
	UNREFERENCED_PARAMETER(sig);
	if (g_WDHandle != INVALID_HANDLE_VALUE) {
		WinDivertClose(g_WDHandle);
		g_WDHandle = INVALID_HANDLE_VALUE;
	} //if
}

/*
 * THe block page contents.
 */
static char custom_output[4096] = { 0 };
static long custom_length = 0;

/*
 * Initialize a PACKET.
 */
static void PacketInit(PPACKET packet)
{
	//memset(packet, 0, sizeof(PACKET));
	packet->ip.Version    = 4;
	packet->ip.HdrLength  = sizeof(WINDIVERT_IPHDR) / sizeof(UINT32);
	packet->ip.Length     = htons(sizeof(PACKET));
	packet->ip.TTL        = 64;
	packet->ip.Protocol   = IPPROTO_TCP;
	packet->tcp.HdrLength = sizeof(WINDIVERT_TCPHDR) / sizeof(UINT32);
}

/*
 * Search for a string in a fixed-length byte string.
 * If partial is true, partial matches are allowed at the end of the buffer.
 * Returns NULL if not found, or a pointer to the start of the first match.
 */
static char *php_ap_memstr(const char *haystack, int haystacklen, char *needle, int needlen, int partial)
{
	int len = haystacklen;
	char *ptr = (char *)haystack;

	/* iterate through first character matches */
	while ((ptr = (char *)memchr(ptr, needle[0], len))) {

		/* calculate length after match */
		len = haystacklen - static_cast<int>(ptr - (char *)haystack);

		/* done if matches up to capacity of buffer */
		if (memcmp(needle, ptr, needlen < len ? needlen : len) == 0 && (partial || len >= needlen)) {
			break;
		} //if

		  /* next character */
		ptr++; len--;
	}

	return ptr;
}

/*
 * Attempt to parse a URL and match it with the blacklist.
 *
 * BUG:
 * - This function makes several assumptions about HTTP requests, such as:
 *      1) The URL will be contained within one packet;
 *      2) The HTTP request begins at a packet boundary;
 *      3) The Host header immediately follows the GET/POST line.
 *   Some browsers, such as Internet Explorer, violate these assumptions
 *   and therefore matching will not work.
 */
static BOOL BlackListPayloadMatch_2(char *data, int len)
{
	static const char *protocol_s[] = { "GET ", "POST ", "HEAD " };
	static const int   protocol_l[] = { 4, 5, 5 };

	if (len < sizeof("POST / HTTP/1.1\r\nHost: \r\n\r\n")) {
		return FALSE;
	} //if

	for (int i = 0; i < _countof(protocol_s); ++i) {
		if (*(int *)data == *(int *)protocol_s[i]) {
			if (protocol_l[i] == sizeof(int) || *(data + sizeof(int)) == ' ') {
				// parse url begin
				const char *lpurl = data + protocol_l[i];
				if (memcmp(lpurl, "http://", sizeof("http://") - 1) == 0/* || memcmp(lpurl, "https://", sizeof("https://") - 1) == 0*/) {
					const char *lpdomain = lpurl + sizeof("http://") - 1;
					const char *lpdomainl = strstr(lpdomain, "/");
					char domain[32];
					memcpy(domain, lpdomain, lpdomainl - lpdomain);
					domain[lpdomainl - lpdomain] = '\0';
					printf("%s\n", domain);
				} else {
					const char *lphost = php_ap_memstr(lpurl, len - static_cast<int>(lpurl - data), "\r\nHost: ", sizeof("\r\nHost: ") - 1, FALSE);
					if (lphost != NULL) {
						lphost += sizeof("\r\nHost: ") - 1;
						const char *lphostl = strstr(lphost, "\r\n");
						char host[32];
						memcpy(host, lphost, lphostl - lphost);
						host[lphostl - lphost] = '\0';
						printf("%s\n", host);
						if (strstr(host, "tx.com.cn")) {
							return TRUE;
						} //if
					} //if
				} //if
			} //if
		} //if
	}

	return FALSE;
}

static BOOL BlackListPayloadMatch(char *data, int size)
{
	static const char *protocol_s[] = { "GET " };
	static const int   protocol_l[] = { 4 };

	if (size < sizeof("POST / HTTP/1.1\r\nHost: \r\n\r\n")) {
		return FALSE;
	} //if

	for (int i = 0; i < _countof(protocol_s); ++i) {
		if (*(int *)data == *(int *)protocol_s[i]) {
			data += protocol_l[i];
			size -= protocol_l[i];
			if (php_ap_memstr(data, size, "github-windows.s3.amazonaws.com", sizeof("github-windows.s3.amazonaws.com") - 1, FALSE)) {		
				auto lpblank = php_ap_memstr(data, size, " ", sizeof(" ") - 1, FALSE);
				if (lpblank) {
					char path[MAX_PATH] = { 0 };
					memcpy(path, data, lpblank - data);
					printf("%s\n", path);

					auto lppath = strrchr(path, '/');
					if (!lppath) lppath = path;

					char s[] = { "HTTP/1.1 302 Moved\r\nConnection: close\r\nLocation: http://127.0.0.1/" };
					char e[] = { "\r\n\r\nMoved" };
					
					
					custom_length = strlen(s);
					memcpy(custom_output, s, custom_length);
					lpblank = custom_output + custom_length;

					custom_length += strlen(lppath);
					memcpy(lpblank, lppath, strlen(lppath));
					lpblank = custom_output + custom_length;

					custom_length += strlen(e);
					memcpy(lpblank, e, strlen(e));

					return TRUE;
				} //if
			} else if (php_ap_memstr(data, size, "127.0.0.1", sizeof("127.0.0.1") - 1, FALSE)) 				{
				auto lpblank = php_ap_memstr(data, size, " ", sizeof(" ") - 1, FALSE);
				if (lpblank) {
					char path[MAX_PATH] = { 0 };
					memcpy(path, data, lpblank - data);
					printf("->%s\n", path);

					auto lppath = strrchr(path, '/');
					if (!lppath) lppath = path;

					if (strstr(lppath, "GitHub.exe.manifest") || strstr(lppath, "GitHub.application")) {
						return FALSE;
					} //if

					char s[] = { "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 5\r\n\r\nMoved" };


					custom_length = strlen(s);
					memcpy(custom_output, s, custom_length);

					return TRUE;
				} //if
			}
		} //if
	}

	return FALSE;
}

/*
 * Entry.
 */
int __cdecl main(int argc, char **argv)
{
	// Initialize the pre-frabricated packets:
	static char blockpage_data[sizeof(PACKET) + sizeof(custom_output)] = { 0 };
	auto blockpage = reinterpret_cast<PDATAPACKET>(blockpage_data);
	PacketInit(&blockpage->header);
	blockpage->header.tcp.SrcPort = htons(80);
	blockpage->header.tcp.Psh     = 1;
	blockpage->header.tcp.Ack     = 1;

	static PACKET reset = { 0 };
	PacketInit(&reset);
	reset.tcp.Rst     = 1;
	reset.tcp.Ack     = 1;
	reset.tcp.DstPort = htons(80);

	static PACKET finish = { 0 };
	PacketInit(&finish);
	finish.tcp.Fin     = 1;
	finish.tcp.Ack     = 1;
	finish.tcp.SrcPort = htons(80);

	// Open the Divert device:
	g_WDHandle = WinDivertOpen("outbound && "              // Outbound traffic only
							   "ip && "                    // Only IPv4 supported
							   "tcp.DstPort == 80 && "     // HTTP (port 80) only
							   "tcp.PayloadLength > 0",    // TCP data packets only
							   WINDIVERT_LAYER_NETWORK,
							   404,						   // Arbitrary
							   0);
	if (g_WDHandle == INVALID_HANDLE_VALUE) {
		fprintf(stderr, "error: failed to open the WinDivert device (%d)\n",
				GetLastError());
	} else {
		printf("OPENED WinDivert\n");
	} //if

	// Install a CTRL+C handler that will do the cleanups on exit:
	signal(SIGINT, ctrlc_handler);

	static char       packet[0xFFFF];
	UINT              packet_len;
	WINDIVERT_ADDRESS addr;
	PWINDIVERT_IPHDR  ip_header;
	PWINDIVERT_TCPHDR tcp_header;
	PVOID             payload;
	UINT              payload_len;
	// Main loop:
	while (g_WDHandle != INVALID_HANDLE_VALUE) 
	{
		if (!WinDivertRecv(g_WDHandle, packet, sizeof(packet), &addr, &packet_len)) {
			fprintf(stderr, "warning: failed to read packet (%d)\n", GetLastError());
			continue;
		} //if

		// Parses raw packet and returns pointers into the original pPacket packet
		if (!WinDivertHelperParsePacket(packet, packet_len, 
										&ip_header, NULL, NULL, NULL, &tcp_header, NULL, &payload, &payload_len) ||
			!BlackListPayloadMatch(static_cast<char *>(payload), payload_len)) {
			// Packet does not match the blacklist; simply reinject it.
			WinDivertHelperCalcChecksums(packet, packet_len,
										 WINDIVERT_HELPER_NO_REPLACE);
			if (!WinDivertSend(g_WDHandle, packet, packet_len, &addr, NULL)) {
				fprintf(stderr, "warning: failed to reinject packet (%d)\n", GetLastError());
			} //if
			continue;
		} //if

		// The URL matched the blacklist; we block it by hijacking the TCP
		// connection.

		// (1) Send a TCP RST to the server; immediately closing the
		//     connection at the server's end.
		reset.ip.SrcAddr  = ip_header->SrcAddr;
		reset.ip.DstAddr  = ip_header->DstAddr;
		reset.tcp.SrcPort = tcp_header->SrcPort;
		reset.tcp.SeqNum  = tcp_header->SeqNum;
		reset.tcp.AckNum  = tcp_header->AckNum;
		WinDivertHelperCalcChecksums(&reset, sizeof(reset), 0);
		if (!WinDivertSend(g_WDHandle, &reset, sizeof(reset), &addr, NULL)) {
			fprintf(stderr, "warning: failed to send reset packet (%d)\n", GetLastError());
		} //if

		// (2) Send the blockpage to the browser:
		blockpage->header.ip.SrcAddr  = ip_header->DstAddr;
		blockpage->header.ip.DstAddr  = ip_header->SrcAddr;
		blockpage->header.tcp.DstPort = tcp_header->SrcPort;
		blockpage->header.tcp.SeqNum  = tcp_header->AckNum;
		blockpage->header.tcp.AckNum  = htonl(ntohl(tcp_header->SeqNum) + payload_len);
		memcpy(blockpage->data, custom_output, custom_length);
		blockpage->header.ip.Length = htons(sizeof(PACKET) + custom_length);
		WinDivertHelperCalcChecksums(blockpage, sizeof(PACKET) + custom_length, 0);
		addr.Direction = !addr.Direction;     // Reverse direction.
		if (!WinDivertSend(g_WDHandle, blockpage, sizeof(PACKET) + custom_length, &addr, NULL)) {
			fprintf(stderr, "warning: failed to send block page packet (%d)\n", GetLastError());
		} //if

		// (3) Send a TCP FIN to the browser; closing the connection at the 
		//     browser's end.
		finish.ip.SrcAddr  = ip_header->DstAddr;
		finish.ip.DstAddr  = ip_header->SrcAddr;
		finish.tcp.DstPort = tcp_header->SrcPort;
		finish.tcp.SeqNum  = htonl(ntohl(tcp_header->AckNum) + custom_length);
		finish.tcp.AckNum  = htonl(ntohl(tcp_header->SeqNum) + payload_len);
		WinDivertHelperCalcChecksums(&finish, sizeof(finish), 0);
		if (!WinDivertSend(g_WDHandle, &finish, sizeof(finish), &addr, NULL)) {
			fprintf(stderr, "warning: failed to send finish packet (%d)\n", GetLastError());
		} //if
	}

	printf("CLOSED WinDivert\n");
}
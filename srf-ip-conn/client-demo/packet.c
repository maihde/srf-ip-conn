/*

Copyright (c) 2016 SharkRF OÜ. https://www.sharkrf.com/
Author: Norbert "Nonoo" Varga, HA2NON

Permission is hereby granted, free of charge, to any person obtaining
a copy of this software and associated documentation files (the "Software"),
to deal in the Software without restriction, including without limitation
the rights to use, copy, modify, merge, publish, distribute, sublicense,
and/or sell copies of the Software, and to permit persons to whom the
Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included
in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
DEALINGS IN THE SOFTWARE.

*/

#include "packet.h"
#include "client.h"
#include "client-sock.h"
#include "config.h"

#include <string.h>
#include <sys/time.h>

typedef struct pcap_hdr_s {
    uint32_t magic_number;   /* magic number */
    uint16_t version_major;  /* major version number */
    uint16_t version_minor;  /* minor version number */
    int32_t  thiszone;       /* GMT to local correction */
    uint32_t sigfigs;        /* accuracy of timestamps */
    uint32_t snaplen;        /* max length of captured packets, in octets */
    uint32_t network;        /* data link type */
} pcap_hdr_t;

typedef struct pcaprec_hdr_s {
    uint32_t ts_sec;         /* timestamp seconds */
    uint32_t ts_usec;        /* timestamp microseconds */
    uint32_t incl_len;       /* number of octets of packet saved in file */
    uint32_t orig_len;       /* actual length of packet */
} pcaprec_hdr_t;

void write_pcap_hdr(FILE *a_file) {
    pcap_hdr_t pcap_hdr;
    pcap_hdr.magic_number = 0xa1b2c3d4;
    pcap_hdr.version_major = 2;
    pcap_hdr.version_minor = 4;
    pcap_hdr.thiszone = 0;
    pcap_hdr.sigfigs = 0;
    pcap_hdr.snaplen = 65535;
    pcap_hdr.network = 147;
    
    fwrite(&pcap_hdr, sizeof(pcap_hdr), 1, a_file);
}

void write_pcap_pkt(FILE *a_file, uint8_t* data, size_t data_len) {
    struct timeval now;
    
    gettimeofday(&now, NULL);

    pcaprec_hdr_t pcaprec_hdr;
    pcaprec_hdr.ts_sec = now.tv_sec;
    pcaprec_hdr.ts_usec = now.tv_usec;
    pcaprec_hdr.incl_len = data_len;
    pcaprec_hdr.orig_len = data_len;
    
    fwrite(&pcaprec_hdr, sizeof(pcaprec_hdr), 1, a_file);
    fwrite(data, data_len, 1, a_file);
}

static void packet_process_token(void) {
	srf_ip_conn_packet_t *packet = (srf_ip_conn_packet_t *)client_sock_received_packet.buf;

	if (client_sock_received_packet.received_bytes != sizeof(srf_ip_conn_packet_header_t)+sizeof(srf_ip_conn_token_payload_t)) {
		printf("  packet is %zd bytes, not %lu, ignoring\n", client_sock_received_packet.received_bytes, sizeof(srf_ip_conn_packet_header_t)+sizeof(srf_ip_conn_token_payload_t));
		return;
	}

	client_got_token(packet->token.token);
}

static void packet_process_ack(void) {
	srf_ip_conn_packet_t *packet = (srf_ip_conn_packet_t *)client_sock_received_packet.buf;

	if (client_sock_received_packet.received_bytes != sizeof(srf_ip_conn_packet_header_t)+sizeof(srf_ip_conn_ack_payload_t)) {
		printf("  packet is %zd bytes, not %lu, ignoring\n", client_sock_received_packet.received_bytes, sizeof(srf_ip_conn_packet_header_t)+sizeof(srf_ip_conn_ack_payload_t));
		return;
	}
	if (!srf_ip_conn_packet_hmac_check(client_token, client_password, packet, sizeof(srf_ip_conn_ack_payload_t))) {
		printf("  invalid hmac, ignoring ack packet\n");
		return;
	}

	client_got_ack(packet->ack.result);
}

static void packet_process_nak(void) {
	srf_ip_conn_packet_t *packet = (srf_ip_conn_packet_t *)client_sock_received_packet.buf;

	if (client_sock_received_packet.received_bytes != sizeof(srf_ip_conn_packet_header_t)+sizeof(srf_ip_conn_nak_payload_t)) {
		printf("  packet is %zd bytes, not %lu, ignoring\n", client_sock_received_packet.received_bytes, sizeof(srf_ip_conn_packet_header_t)+sizeof(srf_ip_conn_nak_payload_t));
		return;
	}
	if (!srf_ip_conn_packet_hmac_check(client_token, client_password, packet, sizeof(srf_ip_conn_nak_payload_t))) {
		printf("  invalid hmac, ignoring nak packet\n");
		return;
	}

	client_got_nak(packet->nak.result);
}

static void packet_process_pong(void) {
	srf_ip_conn_packet_t *packet = (srf_ip_conn_packet_t *)client_sock_received_packet.buf;

	if (client_sock_received_packet.received_bytes != sizeof(srf_ip_conn_packet_header_t)+sizeof(srf_ip_conn_pong_payload_t)) {
		printf("  packet is %zd bytes, not %lu, ignoring\n", client_sock_received_packet.received_bytes, sizeof(srf_ip_conn_packet_header_t)+sizeof(srf_ip_conn_pong_payload_t));
		return;
	}
	if (!srf_ip_conn_packet_hmac_check(client_token, client_password, packet, sizeof(srf_ip_conn_pong_payload_t))) {
		printf("  invalid hmac, ignoring pong packet\n");
		return;
	}

	client_got_pong();
}

static void packet_process_raw(void) {
	srf_ip_conn_packet_t *packet = (srf_ip_conn_packet_t *)client_sock_received_packet.buf;

	if (client_sock_received_packet.received_bytes != sizeof(srf_ip_conn_packet_header_t)+sizeof(srf_ip_conn_data_raw_payload_t)) {
		printf("  packet is %zd bytes, not %lu, ignoring\n", client_sock_received_packet.received_bytes, sizeof(srf_ip_conn_packet_header_t)+sizeof(srf_ip_conn_data_raw_payload_t));
		return;
	}
	if (!srf_ip_conn_packet_hmac_check(client_token, client_password, packet, sizeof(srf_ip_conn_data_raw_payload_t))) {
		printf("  invalid hmac, ignoring packet\n");
		return;
	}

	srf_ip_conn_packet_print_data_raw_payload(&packet->data_raw);
	client_got_valid_packet();
}

static void packet_process_dmr(void) {
	srf_ip_conn_packet_t *packet = (srf_ip_conn_packet_t *)client_sock_received_packet.buf;

	if (client_sock_received_packet.received_bytes != sizeof(srf_ip_conn_packet_header_t)+sizeof(srf_ip_conn_data_dmr_payload_t)) {
		printf("  packet is %zd bytes, not %lu, ignoring\n", client_sock_received_packet.received_bytes, sizeof(srf_ip_conn_packet_header_t)+sizeof(srf_ip_conn_data_dmr_payload_t));
		return;
	}
	if (!srf_ip_conn_packet_hmac_check(client_token, client_password, packet, sizeof(srf_ip_conn_data_dmr_payload_t))) {
		printf("  invalid hmac, ignoring packet\n");
		return;
	}

	srf_ip_conn_packet_print_data_dmr_payload(&packet->data_dmr);
	client_got_valid_packet();
    
    if (output_file) {
        write_pcap_pkt(
            output_file,
            (packet->data_dmr).data,
            sizeof((packet->data_dmr).data)
        );
    }
}

static void packet_process_dstar(void) {
	srf_ip_conn_packet_t *packet = (srf_ip_conn_packet_t *)client_sock_received_packet.buf;

	if (client_sock_received_packet.received_bytes != sizeof(srf_ip_conn_packet_header_t)+sizeof(srf_ip_conn_data_dstar_payload_t)) {
		printf("  packet is %zd bytes, not %lu, ignoring\n", client_sock_received_packet.received_bytes, sizeof(srf_ip_conn_packet_header_t)+sizeof(srf_ip_conn_data_dstar_payload_t));
		return;
	}
	if (!srf_ip_conn_packet_hmac_check(client_token, client_password, packet, sizeof(srf_ip_conn_data_dstar_payload_t))) {
		printf("  invalid hmac, ignoring packet\n");
		return;
	}

	srf_ip_conn_packet_print_data_dstar_payload(&packet->data_dstar);
	client_got_valid_packet();
}

static void packet_process_c4fm(void) {
	srf_ip_conn_packet_t *packet = (srf_ip_conn_packet_t *)client_sock_received_packet.buf;

	if (client_sock_received_packet.received_bytes != sizeof(srf_ip_conn_packet_header_t)+sizeof(srf_ip_conn_data_c4fm_payload_t)) {
		printf("  packet is %zd bytes, not %lu, ignoring\n", client_sock_received_packet.received_bytes, sizeof(srf_ip_conn_packet_header_t)+sizeof(srf_ip_conn_data_c4fm_payload_t));
		return;
	}
	if (!srf_ip_conn_packet_hmac_check(client_token, client_password, packet, sizeof(srf_ip_conn_data_c4fm_payload_t))) {
		printf("  invalid hmac, ignoring packet\n");
		return;
	}

	srf_ip_conn_packet_print_data_c4fm_payload(&packet->data_c4fm);
	client_got_valid_packet();
}

flag_t packet_is_header_valid(void) {
	return (client_sock_received_packet.received_bytes >= sizeof(srf_ip_conn_packet_header_t) &&
			memcmp(client_sock_received_packet.buf, SRF_IP_CONN_MAGIC_STR, SRF_IP_CONN_MAGIC_STR_LENGTH) == 0);
}

void packet_process(void) {
	srf_ip_conn_packet_header_t *header = (srf_ip_conn_packet_header_t *)client_sock_received_packet.buf;
    
    switch (header->version) {
		case 0:
			switch (header->packet_type) {
				case SRF_IP_CONN_PACKET_TYPE_TOKEN:
					packet_process_token();
					break;
				case SRF_IP_CONN_PACKET_TYPE_ACK:
					packet_process_ack();
					break;
				case SRF_IP_CONN_PACKET_TYPE_NAK:
					packet_process_nak();
					break;
				case SRF_IP_CONN_PACKET_TYPE_PONG:
					packet_process_pong();
					break;
				case SRF_IP_CONN_PACKET_TYPE_DATA_RAW:
					packet_process_raw();
					break;
				case SRF_IP_CONN_PACKET_TYPE_DATA_DMR:
					packet_process_dmr();
					break;
				case SRF_IP_CONN_PACKET_TYPE_DATA_DSTAR:
					packet_process_dstar();
					break;
				case SRF_IP_CONN_PACKET_TYPE_DATA_C4FM:
					packet_process_c4fm();
					break;
			}
			break;
	}
}

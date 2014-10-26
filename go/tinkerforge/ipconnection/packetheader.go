package ipconnection

import (
	"fmt"
	"log"
	"strings"
)

type PacketHeader struct {
	uid uint32
	length uint8
	function_id uint8
	sequence_number_and_options uint8
	error_code_and_future_use uint8
}


int packet_header_create(PacketHeader *header, uint8_t length,
                         uint8_t function_id, IPConnectionPrivate *ipcon_p,
                         DevicePrivate *device_p) {
	uint8_t sequence_number;
	bool response_expected = false;
	int ret = E_OK;

	mutex_lock(&ipcon_p->sequence_number_mutex);

	sequence_number = ipcon_p->next_sequence_number + 1;
	ipcon_p->next_sequence_number = sequence_number % 15;

	mutex_unlock(&ipcon_p->sequence_number_mutex);

	memset(header, 0, sizeof(PacketHeader));

	if (device_p != NULL) {
		header->uid = leconvert_uint32_to(device_p->uid);
	}

	header->length = length;
	header->function_id = function_id;
	packet_header_set_sequence_number(header, sequence_number);

	if (device_p != NULL) {
		ret = device_get_response_expected(device_p, function_id, &response_expected);
		packet_header_set_response_expected(header, response_expected ? 1 : 0);
	}

	return ret;
}

uint8_t packet_header_get_sequence_number(PacketHeader *header) {
	return (header->sequence_number_and_options >> 4) & 0x0F;
}

void packet_header_set_sequence_number(PacketHeader *header,
                                       uint8_t sequence_number) {
	header->sequence_number_and_options |= (sequence_number << 4) & 0xF0;
}

uint8_t packet_header_get_response_expected(PacketHeader *header) {
	return (header->sequence_number_and_options >> 3) & 0x01;
}

void packet_header_set_response_expected(PacketHeader *header,
                                         uint8_t response_expected) {
	header->sequence_number_and_options |= (response_expected << 3) & 0x08;
}

uint8_t packet_header_get_error_code(PacketHeader *header) {
	return (header->error_code_and_future_use >> 6) & 0x03;
}


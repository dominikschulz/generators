package ipconnection

import (
	"fmt"
	"log"
	"strings"
)


const (
	E_OK = 0
	E_TIMEOUT = -1
	E_NO_STREAM_SOCKET = -2
	E_HOSTNAME_INVALID = -3
	E_NO_CONNECT = -4
	E_NO_THREAD = -5
	E_NOT_ADDED = -6 // unused since v2.0
	E_ALREADY_CONNECTED = -7
	E_NOT_CONNECTED = -8
	E_INVALID_PARAMETER = -9 // error response from device
	E_NOT_SUPPORTED = -10 // error response from device
	E_UNKNOWN_ERROR_CODE = -11 // error response from device
)

func leconvert_int16_to(native int16) int16 {
	return leconvert_uint16_to(native);
}

func leconvert_uint16_to(native uint16) {
	union {
		uint8_t bytes[2];
		uint16_t little;
	} c;

	c.bytes[0] = (native >> 0) & 0xFF;
	c.bytes[1] = (native >> 8) & 0xFF;

	return c.little;
}

int32_t leconvert_int32_to(int32_t native) {
	return leconvert_uint32_to(native);
}

uint32_t leconvert_uint32_to(uint32_t native) {
	union {
		uint8_t bytes[4];
		uint32_t little;
	} c;

	c.bytes[0] = (native >>  0) & 0xFF;
	c.bytes[1] = (native >>  8) & 0xFF;
	c.bytes[2] = (native >> 16) & 0xFF;
	c.bytes[3] = (native >> 24) & 0xFF;

	return c.little;
}

int64_t leconvert_int64_to(int64_t native) {
	return leconvert_uint64_to(native);
}

uint64_t leconvert_uint64_to(uint64_t native) {
	union {
		uint8_t bytes[8];
		uint64_t little;
	} c;

	c.bytes[0] = (native >>  0) & 0xFF;
	c.bytes[1] = (native >>  8) & 0xFF;
	c.bytes[2] = (native >> 16) & 0xFF;
	c.bytes[3] = (native >> 24) & 0xFF;
	c.bytes[4] = (native >> 32) & 0xFF;
	c.bytes[5] = (native >> 40) & 0xFF;
	c.bytes[6] = (native >> 48) & 0xFF;
	c.bytes[7] = (native >> 56) & 0xFF;

	return c.little;
}

float leconvert_float_to(float native) {
	union {
		uint32_t u;
		float f;
	} c;

	c.f = native;
	c.u = leconvert_uint32_to(c.u);

	return c.f;
}

int16_t leconvert_int16_from(int16_t little) {
	return leconvert_uint16_from(little);
}

uint16_t leconvert_uint16_from(uint16_t little) {
	uint8_t *bytes = (uint8_t *)&little;

	return ((uint16_t)bytes[1] << 8) |
	        (uint16_t)bytes[0];
}

int32_t leconvert_int32_from(int32_t little) {
	return leconvert_uint32_from(little);
}

uint32_t leconvert_uint32_from(uint32_t little) {
	uint8_t *bytes = (uint8_t *)&little;

	return ((uint32_t)bytes[3] << 24) |
	       ((uint32_t)bytes[2] << 16) |
	       ((uint32_t)bytes[1] <<  8) |
	        (uint32_t)bytes[0];
}

int64_t leconvert_int64_from(int64_t little) {
	return leconvert_uint64_from(little);
}

uint64_t leconvert_uint64_from(uint64_t little) {
	uint8_t *bytes = (uint8_t *)&little;

	return ((uint64_t)bytes[7] << 56) |
	       ((uint64_t)bytes[6] << 48) |
	       ((uint64_t)bytes[5] << 40) |
	       ((uint64_t)bytes[4] << 32) |
	       ((uint64_t)bytes[3] << 24) |
	       ((uint64_t)bytes[2] << 16) |
	       ((uint64_t)bytes[1] <<  8) |
	        (uint64_t)bytes[0];
}

float leconvert_float_from(float little) {
	union {
		uint32_t u;
		float f;
	} c;

	c.f = little;
	c.u = leconvert_uint32_from(c.u);

	return c.f;
}


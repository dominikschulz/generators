package ipconnection

import (
	"fmt"
	"log"
	"strings"
)


const (
	BRICK_DAEMON_FUNCTION_GET_AUTHENTICATION_NONCE = 1
	BRICK_DAEMON_FUNCTION_AUTHENTICATE = 2
)

type BrickDaemon Device

func NewBrickd(BrickDaemon *brickd, const char *uid, IPConnection *ipcon) BrickDaemon {
	DevicePrivate *device_p;

	device_create(brickd, uid, ipcon->p, 2, 0, 0);

	device_p = brickd->p;

	device_p->response_expected[BRICK_DAEMON_FUNCTION_GET_AUTHENTICATION_NONCE] = DEVICE_RESPONSE_EXPECTED_ALWAYS_TRUE;
	device_p->response_expected[BRICK_DAEMON_FUNCTION_AUTHENTICATE] = DEVICE_RESPONSE_EXPECTED_TRUE;
}

/*
TODO destructor
static void brickd_destroy(BrickDaemon *brickd) {
	device_release(brickd->p);
}
*/

func (b *BrickDaemon) GetAuthenticationNonce() []uint8, err {
	var request GetAuthenticationNonce
	var response GetAuthenticationNonceResponse
	var err error

	err = NewPacketHeader(&request.header, sizeof(request), BRICK_DAEMON_FUNCTION_GET_AUTHENTICATION_NONCE, device_p->ipcon_p, device_p);
	if err != nil {
		return [], err
	}

	err = b.SendRequest(&request, &response)
	if err != nil {
		return [], err
	}

	return response.server_none
}

func (b *BrickDaemon) Authenticate(client_nonce []uint8, digest []uint8) int {
	DevicePrivate *device_p = brickd->p
	Authenticate request
	var err error

	err = NewPacketHeader(&request.header, sizeof(request), BRICK_DAEMON_FUNCTION_AUTHENTICATE, device_p->ipcon_p, device_p);
	if err != nil {
		return [], err
	}

	memcpy(request.client_nonce, client_nonce, 4 * sizeof(uint8_t));
	memcpy(request.digest, digest, 20 * sizeof(uint8_t));

	ret = device_send_request(device_p, (Packet *)&request, NULL);

	return ret;
}


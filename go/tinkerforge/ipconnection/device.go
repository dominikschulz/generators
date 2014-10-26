package ipconnection

import (
	"fmt"
	"log"
	"strings"
)


type Device struct {
	refCount int
	uid uint32
	ipcon IPConnection
	api_version []uint8
	request_mutex sync.Mutex
	uint8_t expected_response_function_id // protected by request_mutex
	uint8_t expected_response_sequence_number // protected by request_mutex
	Mutex response_mutex
	Packet response_packet // protected by response_mutex
	Event response_event
	response_expected []int
	registered_callbacks []*interface{}
	registered_callback_user_data []*interface{}
	callback_wrappers []CallbackWrapperFunction
}

/**
 * \internal
 */
const (
	DEVICE_RESPONSE_EXPECTED_INVALID_FUNCTION_ID = 0
	DEVICE_RESPONSE_EXPECTED_ALWAYS_TRUE = 1 // getter
	DEVICE_RESPONSE_EXPECTED_ALWAYS_FALSE = 2 // callback
	DEVICE_RESPONSE_EXPECTED_TRUE = 3 // setter
	DEVICE_RESPONSE_EXPECTED_FALSE = 4 // setter, default
)

/**
 * \internal
 */
void device_create(Device *device, const char *uid,
                   IPConnectionPrivate *ipcon_p, uint8_t api_version_major,
                   uint8_t api_version_minor, uint8_t api_version_release);

/**
 * \internal
 */
void device_release(DevicePrivate *device_p);

/**
 * \internal
 */
int device_get_response_expected(DevicePrivate *device_p, uint8_t function_id,
                                 bool *ret_response_expected);

/**
 * \internal
 */
int device_set_response_expected(DevicePrivate *device_p, uint8_t function_id,
                                 bool response_expected);

/**
 * \internal
 */
int device_set_response_expected_all(DevicePrivate *device_p, bool response_expected);

/**
 * \internal
 */
void device_register_callback(DevicePrivate *device_p, uint8_t id, void *callback,
                              void *user_data);

/**
 * \internal
 */
int device_get_api_version(DevicePrivate *device_p, uint8_t ret_api_version[3]);

/**
 * \internal
 */
int device_send_request(DevicePrivate *device_p, Packet *request, Packet *response);

const (
	IPCON_FUNCTION_ENUMERATE = 254
)

static int ipcon_send_request(IPConnectionPrivate *ipcon_p, Packet *request);

// NOTE: assumes device_p->ref_count == 0
static void device_destroy(DevicePrivate *device_p) {
	table_remove(&device_p->ipcon_p->devices, device_p->uid);

	event_destroy(&device_p->response_event);

	mutex_destroy(&device_p->response_mutex);

	mutex_destroy(&device_p->request_mutex);

	free(device_p);
}

void device_create(Device *device, const char *uid_str,
                   IPConnectionPrivate *ipcon_p, uint8_t api_version_major,
                   uint8_t api_version_minor, uint8_t api_version_release) {
	DevicePrivate *device_p;
	uint64_t uid;
	uint32_t value1;
	uint32_t value2;
	int i;

	device_p = (DevicePrivate *)malloc(sizeof(DevicePrivate));
	device->p = device_p;

	uid = base58_decode(uid_str);

	if (uid > 0xFFFFFFFF) {
		// convert from 64bit to 32bit
		value1 = uid & 0xFFFFFFFF;
		value2 = (uid >> 32) & 0xFFFFFFFF;

		uid  = (value1 & 0x00000FFF);
		uid |= (value1 & 0x0F000000) >> 12;
		uid |= (value2 & 0x0000003F) << 16;
		uid |= (value2 & 0x000F0000) << 6;
		uid |= (value2 & 0x3F000000) << 2;
	}

	device_p->ref_count = 1;

	device_p->uid = uid & 0xFFFFFFFF;

	device_p->ipcon_p = ipcon_p;

	device_p->api_version[0] = api_version_major;
	device_p->api_version[1] = api_version_minor;
	device_p->api_version[2] = api_version_release;

	// request
	mutex_create(&device_p->request_mutex);

	// response
	device_p->expected_response_function_id = 0;
	device_p->expected_response_sequence_number = 0;

	mutex_create(&device_p->response_mutex);

	memset(&device_p->response_packet, 0, sizeof(Packet));

	event_create(&device_p->response_event);

	for (i = 0; i < DEVICE_NUM_FUNCTION_IDS; i++) {
		device_p->response_expected[i] = DEVICE_RESPONSE_EXPECTED_INVALID_FUNCTION_ID;
	}

	device_p->response_expected[IPCON_FUNCTION_ENUMERATE] = DEVICE_RESPONSE_EXPECTED_ALWAYS_FALSE;
	device_p->response_expected[IPCON_CALLBACK_ENUMERATE] = DEVICE_RESPONSE_EXPECTED_ALWAYS_FALSE;

	// callbacks
	for (i = 0; i < DEVICE_NUM_FUNCTION_IDS; i++) {
		device_p->registered_callbacks[i] = NULL;
		device_p->registered_callback_user_data[i] = NULL;
		device_p->callback_wrappers[i] = NULL;
	}

	// add to IPConnection
	table_insert(&ipcon_p->devices, device_p->uid, device_p);
}

void device_release(DevicePrivate *device_p) {
	IPConnectionPrivate *ipcon_p = device_p->ipcon_p;

	mutex_lock(&ipcon_p->devices_ref_mutex);

	--device_p->ref_count;

	if (device_p->ref_count == 0) {
		device_destroy(device_p);
	}

	mutex_unlock(&ipcon_p->devices_ref_mutex);
}

int device_get_response_expected(DevicePrivate *device_p, uint8_t function_id,
                                 bool *ret_response_expected) {
	int flag = device_p->response_expected[function_id];

	if (flag == DEVICE_RESPONSE_EXPECTED_INVALID_FUNCTION_ID) {
		return E_INVALID_PARAMETER;
	}

	if (flag == DEVICE_RESPONSE_EXPECTED_ALWAYS_TRUE ||
	    flag == DEVICE_RESPONSE_EXPECTED_TRUE) {
		*ret_response_expected = true;
	} else {
		*ret_response_expected = false;
	}

	return E_OK;
}

int device_set_response_expected(DevicePrivate *device_p, uint8_t function_id,
                                 bool response_expected) {
	int current_flag = device_p->response_expected[function_id];

	if (current_flag != DEVICE_RESPONSE_EXPECTED_TRUE &&
	    current_flag != DEVICE_RESPONSE_EXPECTED_FALSE) {
		return E_INVALID_PARAMETER;
	}

	device_p->response_expected[function_id] =
	    response_expected ? DEVICE_RESPONSE_EXPECTED_TRUE
	                      : DEVICE_RESPONSE_EXPECTED_FALSE;

	return E_OK;
}

int device_set_response_expected_all(DevicePrivate *device_p, bool response_expected) {
	int flag = response_expected ? DEVICE_RESPONSE_EXPECTED_TRUE
	                             : DEVICE_RESPONSE_EXPECTED_FALSE;
	int i;

	for (i = 0; i < DEVICE_NUM_FUNCTION_IDS; ++i) {
		if (device_p->response_expected[i] == DEVICE_RESPONSE_EXPECTED_TRUE ||
		    device_p->response_expected[i] == DEVICE_RESPONSE_EXPECTED_FALSE) {
			device_p->response_expected[i] = flag;
		}
	}

	return E_OK;
}

void device_register_callback(DevicePrivate *device_p, uint8_t id, void *callback,
                              void *user_data) {
	device_p->registered_callbacks[id] = callback;
	device_p->registered_callback_user_data[id] = user_data;
}

int device_get_api_version(DevicePrivate *device_p, uint8_t ret_api_version[3]) {
	ret_api_version[0] = device_p->api_version[0];
	ret_api_version[1] = device_p->api_version[1];
	ret_api_version[2] = device_p->api_version[2];

	return E_OK;
}

int device_send_request(DevicePrivate *device_p, Packet *request, Packet *response) {
	int ret = E_OK;
	uint8_t sequence_number = packet_header_get_sequence_number(&request->header);
	uint8_t response_expected = packet_header_get_response_expected(&request->header);
	uint8_t error_code;

	if (response_expected) {
		mutex_lock(&device_p->request_mutex);

		event_reset(&device_p->response_event);

		device_p->expected_response_function_id = request->header.function_id;
		device_p->expected_response_sequence_number = sequence_number;
	}

	ret = ipcon_send_request(device_p->ipcon_p, request);

	if (ret != E_OK) {
		if (response_expected) {
			mutex_unlock(&device_p->request_mutex);
		}

		return ret;
	}

	if (response_expected) {
		if (event_wait(&device_p->response_event, device_p->ipcon_p->timeout) < 0) {
			ret = E_TIMEOUT;
		}

		device_p->expected_response_function_id = 0;
		device_p->expected_response_sequence_number = 0;

		event_reset(&device_p->response_event);

		if (ret == E_OK) {
			mutex_lock(&device_p->response_mutex);

			error_code = packet_header_get_error_code(&device_p->response_packet.header);

			if (device_p->response_packet.header.function_id != request->header.function_id ||
			    packet_header_get_sequence_number(&device_p->response_packet.header) != sequence_number) {
				ret = E_TIMEOUT;
			} else if (error_code == 0) {
				// no error
				if (response != NULL) {
					memcpy(response, &device_p->response_packet,
					       device_p->response_packet.header.length);
				}
			} else if (error_code == 1) {
				ret = E_INVALID_PARAMETER;
			} else if (error_code == 2) {
				ret = E_NOT_SUPPORTED;
			} else {
				ret = E_UNKNOWN_ERROR_CODE;
			}

			mutex_unlock(&device_p->response_mutex);
		}

		mutex_unlock(&device_p->request_mutex);
	}

	return ret;
}


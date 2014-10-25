package ipconnection
/*
 * Copyright (C) 2012-2014 Matthias Bolte <matthias@tinkerforge.com>
 * Copyright (C) 2011 Olaf Lüke <olaf@tinkerforge.com>
 *
 * Redistribution and use in source and binary forms of this file,
 * with or without modification, are permitted. See the Creative
 * Commons Zero (CC0 1.0) License for more details.
 */

import (
	"strings"
	"fmt"
	"log"
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

type Event struct {
	pthread_cond_t condition;
	pthread_mutex_t mutex;
	bool flag;
} Event;

type Semaphore struct {
	sem_t object;
	sem_t *pointer;
} Semaphore;

type Thread struct {
	pthread_t handle;
	ThreadFunction function;
	void *opaque;
} Thread;

type Table struct {
	Mutex mutex;
	int used;
	int allocated;
	uint32_t *keys;
	void **values;
} Table;

type _QueueItem struct {
	struct _QueueItem *next;
	int kind;
	void *data;
} QueueItem;

type Queue struct {
	Mutex mutex;
	Semaphore semaphore;
	QueueItem *head;
	QueueItem *tail;
}

type PacketHeader struct {
	uid uint32;
	length uint8;
	function_id uint8;
	sequence_number_and_options uint8;
	error_code_and_future_use uint8;
}

type Packet struct {
	PacketHeader header;
	uint8_t payload[64];
	uint8_t optional_data[8];
}

typedef void (*EnumerateCallbackFunction)(const char *uid,
                                          const char *connected_uid,
                                          char position,
                                          uint8_t hardware_version[3],
                                          uint8_t firmware_version[3],
                                          uint16_t device_identifier,
                                          uint8_t enumeration_type,
                                          void *user_data);
typedef void (*ConnectedCallbackFunction)(uint8_t connect_reason,
                                          void *user_data);
typedef void (*DisconnectedCallbackFunction)(uint8_t disconnect_reason,
                                             void *user_data);

#ifdef IPCON_EXPOSE_INTERNALS

typedef void (*CallbackWrapperFunction)(DevicePrivate *device_p, Packet *packet);

#endif

/**
 * \internal
 */
struct _Device {
	DevicePrivate *p;
};

#ifdef IPCON_EXPOSE_INTERNALS

#define DEVICE_NUM_FUNCTION_IDS 256

/**
 * \internal
 */
struct _DevicePrivate {
	int ref_count;

	uint32_t uid;

	IPConnectionPrivate *ipcon_p;

	uint8_t api_version[3];

	Mutex request_mutex;

	uint8_t expected_response_function_id; // protected by request_mutex
	uint8_t expected_response_sequence_number; // protected by request_mutex
	Mutex response_mutex;
	Packet response_packet; // protected by response_mutex
	Event response_event;
	int response_expected[DEVICE_NUM_FUNCTION_IDS];

	void *registered_callbacks[DEVICE_NUM_FUNCTION_IDS];
	void *registered_callback_user_data[DEVICE_NUM_FUNCTION_IDS];
	CallbackWrapperFunction callback_wrappers[DEVICE_NUM_FUNCTION_IDS];
};

/**
 * \internal
 */
enum {
	DEVICE_RESPONSE_EXPECTED_INVALID_FUNCTION_ID = 0,
	DEVICE_RESPONSE_EXPECTED_ALWAYS_TRUE, // getter
	DEVICE_RESPONSE_EXPECTED_ALWAYS_FALSE, // callback
	DEVICE_RESPONSE_EXPECTED_TRUE, // setter
	DEVICE_RESPONSE_EXPECTED_FALSE // setter, default
};

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

#endif // IPCON_EXPOSE_INTERNALS

/**
 * \ingroup IPConnection
 *
 * Possible IDs for ipcon_register_callback.
 */
const (
	IPCON_CALLBACK_ENUMERATE = 253
	IPCON_CALLBACK_CONNECTED = 0
	IPCON_CALLBACK_DISCONNECTED = 1
)

/**
 * \ingroup IPConnection
 *
 * Possible values for enumeration_type parameter of EnumerateCallback.
 */
const (
	IPCON_ENUMERATION_TYPE_AVAILABLE = 0
	IPCON_ENUMERATION_TYPE_CONNECTED = 1
	IPCON_ENUMERATION_TYPE_DISCONNECTED = 2
)

/**
 * \ingroup IPConnection
 *
 * Possible values for connect_reason parameter of ConnectedCallback.
 */
const (
	IPCON_CONNECT_REASON_REQUEST = 0
	IPCON_CONNECT_REASON_AUTO_RECONNECT = 1
)

/**
 * \ingroup IPConnection
 *
 * Possible values for disconnect_reason parameter of DisconnectedCallback.
 */
enum {
	IPCON_DISCONNECT_REASON_REQUEST = 0,
	IPCON_DISCONNECT_REASON_ERROR = 1,
	IPCON_DISCONNECT_REASON_SHUTDOWN = 2
};

/**
 * \ingroup IPConnection
 *
 * Possible return values of ipcon_get_connection_state.
 */
enum {
	IPCON_CONNECTION_STATE_DISCONNECTED = 0,
	IPCON_CONNECTION_STATE_CONNECTED = 1,
	IPCON_CONNECTION_STATE_PENDING = 2 // auto-reconnect in progress
};

/**
 * \internal
 */
struct _IPConnection {
	IPConnectionPrivate *p;
};

#ifdef IPCON_EXPOSE_INTERNALS

#define IPCON_NUM_CALLBACK_IDS 256
#define IPCON_MAX_SECRET_LENGTH 64

/**
 * \internal
 */
typedef Device BrickDaemon;

/**
 * \internal
 */
struct _IPConnectionPrivate {
#ifdef _WIN32
	bool wsa_startup_done; // protected by socket_mutex
#endif

	char *host;
	uint16_t port;

	uint32_t timeout; // in msec

	bool auto_reconnect;
	bool auto_reconnect_allowed;
	bool auto_reconnect_pending;

	Mutex sequence_number_mutex;
	uint8_t next_sequence_number; // protected by sequence_number_mutex

	Mutex authentication_mutex; // protects authentication handshake
	uint32_t next_authentication_nonce; // protected by authentication_mutex

	Mutex devices_ref_mutex; // protects DevicePrivate.ref_count
	Table devices;

	void *registered_callbacks[IPCON_NUM_CALLBACK_IDS];
	void *registered_callback_user_data[IPCON_NUM_CALLBACK_IDS];

	Mutex socket_mutex;
	Socket *socket; // protected by socket_mutex
	uint64_t socket_id; // protected by socket_mutex

	bool receive_flag;
	Thread receive_thread; // protected by socket_mutex

	CallbackContext *callback;

	bool disconnect_probe_flag;
	Thread disconnect_probe_thread; // protected by socket_mutex
	Event disconnect_probe_event;

	Semaphore wait;

	BrickDaemon brickd;
};

#endif // IPCON_EXPOSE_INTERNALS

/**
 * \ingroup IPConnection
 *
 * Creates an IP Connection object that can be used to enumerate the available
 * devices. It is also required for the constructor of Bricks and Bricklets.
 */
void ipcon_create(IPConnection *ipcon);

/**
 * \ingroup IPConnection
 *
 * Destroys the IP Connection object. Calls ipcon_disconnect internally.
 * The connection to the Brick Daemon gets closed and the threads of the
 * IP Connection are terminated.
 */
void ipcon_destroy(IPConnection *ipcon);

/**
 * \ingroup IPConnection
 *
 * Creates a TCP/IP connection to the given \c host and c\ port. The host and
 * port can point to a Brick Daemon or to a WIFI/Ethernet Extension.
 *
 * Devices can only be controlled when the connection was established
 * successfully.
 *
 * Blocks until the connection is established and returns an error code if
 * there is no Brick Daemon or WIFI/Ethernet Extension listening at the given
 * host and port.
 */
int ipcon_connect(IPConnection *ipcon, const char *host, uint16_t port);

/**
 * \ingroup IPConnection
 *
 * Disconnects the TCP/IP connection from the Brick Daemon or the WIFI/Ethernet
 * Extension.
 */
int ipcon_disconnect(IPConnection *ipcon);

/**
 * \ingroup IPConnection
 *
 * Performs an authentication handshake with the connected Brick Daemon or
 * WIFI/Ethernet Extension. If the handshake succeeds the connection switches
 * from non-authenticated to authenticated state and communication can
 * continue as normal. If the handshake fails then the connection gets closed.
 * Authentication can fail if the wrong secret was used or if authentication
 * is not enabled at all on the Brick Daemon or the WIFI/Ethernet Extension.
 *
 * For more information about authentication see
 * http://www.tinkerforge.com/en/doc/Tutorials/Tutorial_Authentication/Tutorial.html
 */
int ipcon_authenticate(IPConnection *ipcon, const char secret[64]);

/**
 * \ingroup IPConnection
 *
 * Can return the following states:
 *
 * - IPCON_CONNECTION_STATE_DISCONNECTED: No connection is established.
 * - IPCON_CONNECTION_STATE_CONNECTED: A connection to the Brick Daemon or
 *   the WIFI/Ethernet Extension is established.
 * - IPCON_CONNECTION_STATE_PENDING: IP Connection is currently trying to
 *   connect.
 */
int ipcon_get_connection_state(IPConnection *ipcon);

/**
 * \ingroup IPConnection
 *
 * Enables or disables auto-reconnect. If auto-reconnect is enabled,
 * the IP Connection will try to reconnect to the previously given
 * host and port, if the connection is lost.
 *
 * Default value is *true*.
 */
void ipcon_set_auto_reconnect(IPConnection *ipcon, bool auto_reconnect);

/**
 * \ingroup IPConnection
 *
 * Returns *true* if auto-reconnect is enabled, *false* otherwise.
 */
bool ipcon_get_auto_reconnect(IPConnection *ipcon);

/**
 * \ingroup IPConnection
 *
 * Sets the timeout in milliseconds for getters and for setters for which the
 * response expected flag is activated.
 *
 * Default timeout is 2500.
 */
void ipcon_set_timeout(IPConnection *ipcon, uint32_t timeout);

/**
 * \ingroup IPConnection
 *
 * Returns the timeout as set by ipcon_set_timeout.
 */
uint32_t ipcon_get_timeout(IPConnection *ipcon);

/**
 * \ingroup IPConnection
 *
 * Broadcasts an enumerate request. All devices will respond with an enumerate
 * callback.
 */
int ipcon_enumerate(IPConnection *ipcon);

/**
 * \ingroup IPConnection
 *
 * Stops the current thread until ipcon_unwait is called.
 *
 * This is useful if you rely solely on callbacks for events, if you want
 * to wait for a specific callback or if the IP Connection was created in
 * a thread.
 *
 * ipcon_wait and ipcon_unwait act in the same way as "acquire" and "release"
 * of a semaphore.
 */
void ipcon_wait(IPConnection *ipcon);

/**
 * \ingroup IPConnection
 *
 * Unwaits the thread previously stopped by ipcon_wait.
 *
 * ipcon_wait and ipcon_unwait act in the same way as "acquire" and "release"
 * of a semaphore.
 */
void ipcon_unwait(IPConnection *ipcon);

/**
 * \ingroup IPConnection
 *
 * Registers a callback for a given ID.
 */
void ipcon_register_callback(IPConnection *ipcon, uint8_t id,
                             void *callback, void *user_data);

#ifdef IPCON_EXPOSE_INTERNALS

/**
 * \internal
 */
int packet_header_create(PacketHeader *header, uint8_t length,
                         uint8_t function_id, IPConnectionPrivate *ipcon_p,
                         DevicePrivate *device_p);

/**
 * \internal
 */
uint8_t packet_header_get_sequence_number(PacketHeader *header);

/**
 * \internal
 */
void packet_header_set_sequence_number(PacketHeader *header,
                                       uint8_t sequence_number);

/**
 * \internal
 */
uint8_t packet_header_get_response_expected(PacketHeader *header);

/**
 * \internal
 */
void packet_header_set_response_expected(PacketHeader *header,
                                         uint8_t response_expected);

/**
 * \internal
 */
uint8_t packet_header_get_error_code(PacketHeader *header);

/**
 * \internal
 */
int16_t leconvert_int16_to(int16_t native);

/**
 * \internal
 */
uint16_t leconvert_uint16_to(uint16_t native);

/**
 * \internal
 */
int32_t leconvert_int32_to(int32_t native);

/**
 * \internal
 */
uint32_t leconvert_uint32_to(uint32_t native);

/**
 * \internal
 */
int64_t leconvert_int64_to(int64_t native);

/**
 * \internal
 */
uint64_t leconvert_uint64_to(uint64_t native);

/**
 * \internal
 */
float leconvert_float_to(float native);

/**
 * \internal
 */
int16_t leconvert_int16_from(int16_t little);

/**
 * \internal
 */
uint16_t leconvert_uint16_from(uint16_t little);

/**
 * \internal
 */
int32_t leconvert_int32_from(int32_t little);

/**
 * \internal
 */
uint32_t leconvert_uint32_from(uint32_t little);

/**
 * \internal
 */
int64_t leconvert_int64_from(int64_t little);

/**
 * \internal
 */
uint64_t leconvert_uint64_from(uint64_t little);

/**
 * \internal
 */
float leconvert_float_from(float little);

#endif // IPCON_EXPOSE_INTERNALS

#ifdef __cplusplus
}
#endif

#endif
/*
 * Copyright (C) 2012-2014 Matthias Bolte <matthias@tinkerforge.com>
 * Copyright (C) 2011 Olaf Lüke <olaf@tinkerforge.com>
 *
 * Redistribution and use in source and binary forms of this file,
 * with or without modification, are permitted. See the Creative
 * Commons Zero (CC0 1.0) License for more details.
 */

#ifndef _WIN32
	#ifndef _BSD_SOURCE
		#define _BSD_SOURCE // for usleep from unistd.h
	#endif
	#ifndef _GNU_SOURCE
		#define _GNU_SOURCE
	#endif
#endif

#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
	#include <winsock2.h>
	#include <wincrypt.h>
	#include <process.h>
#else
	#include <fcntl.h>
	#include <unistd.h>
	#include <sys/types.h>
	#include <sys/socket.h> // connect
	#include <sys/select.h>
	#include <sys/stat.h>
	#include <netinet/tcp.h> // TCP_NO_DELAY
	#include <netdb.h> // gethostbyname
	#include <netinet/in.h> // struct sockaddr_in
#endif

#ifdef _MSC_VER
	// replace getpid with GetCurrentProcessId
	#define getpid GetCurrentProcessId
#else
	#include <sys/time.h> // gettimeofday
#endif

#define IPCON_EXPOSE_INTERNALS

#include "ip_connection.h"

#ifdef __cplusplus
extern "C" {
#endif

#if defined _MSC_VER || defined __BORLANDC__
	#pragma pack(push)
	#pragma pack(1)
	#define ATTRIBUTE_PACKED
#elif defined __GNUC__
	#ifdef _WIN32
		// workaround struct packing bug in GCC 4.7 on Windows
		// http://gcc.gnu.org/bugzilla/show_bug.cgi?id=52991
		#define ATTRIBUTE_PACKED __attribute__((gcc_struct, packed))
	#else
		#define ATTRIBUTE_PACKED __attribute__((packed))
	#endif
#else
	#error unknown compiler, do not know how to enable struct packing
#endif

typedef struct {
	PacketHeader header;
} ATTRIBUTE_PACKED Enumerate;

typedef struct {
	PacketHeader header;
	char uid[8];
	char connected_uid[8];
	char position;
	uint8_t hardware_version[3];
	uint8_t firmware_version[3];
	uint16_t device_identifier;
	uint8_t enumeration_type;
} ATTRIBUTE_PACKED EnumerateCallback;

typedef struct {
	PacketHeader header;
} ATTRIBUTE_PACKED GetAuthenticationNonce;

typedef struct {
	PacketHeader header;
	uint8_t server_nonce[4];
} ATTRIBUTE_PACKED GetAuthenticationNonceResponse;

typedef struct {
	PacketHeader header;
	uint8_t client_nonce[4];
	uint8_t digest[20];
} ATTRIBUTE_PACKED Authenticate;

#if defined _MSC_VER || defined __BORLANDC__
	#pragma pack(pop)
#endif
#undef ATTRIBUTE_PACKED

#ifndef __cplusplus
	#ifdef __GNUC__
		#ifndef __GNUC_PREREQ
			#define __GNUC_PREREQ(major, minor) \
				((((__GNUC__) << 16) + (__GNUC_MINOR__)) >= (((major) << 16) + (minor)))
		#endif
		#if __GNUC_PREREQ(4, 6)
			#define STATIC_ASSERT(condition, message) \
				_Static_assert(condition, message)
		#else
			#define STATIC_ASSERT(condition, message) // FIXME
		#endif
	#else
		#define STATIC_ASSERT(condition, message) // FIXME
	#endif

	STATIC_ASSERT(sizeof(PacketHeader) == 8, "PacketHeader has invalid size");
	STATIC_ASSERT(sizeof(Packet) == 80, "Packet has invalid size");
	STATIC_ASSERT(sizeof(EnumerateCallback) == 34, "EnumerateCallback has invalid size");
	STATIC_ASSERT(sizeof(GetAuthenticationNonce) == 8, "GetAuthenticationNonce has invalid size");
	STATIC_ASSERT(sizeof(GetAuthenticationNonceResponse) == 12, "GetAuthenticationNonceResponse has invalid size");
	STATIC_ASSERT(sizeof(Authenticate) == 32, "Authenticate has invalid size");
#endif

/*****************************************************************************
 *
 *                                 Event
 *
 *****************************************************************************/

#ifdef _WIN32

static void event_create(Event *event) {
	event->handle = CreateEvent(NULL, TRUE, FALSE, NULL);
}

static void event_destroy(Event *event) {
	CloseHandle(event->handle);
}

static void event_set(Event *event) {
	SetEvent(event->handle);
}

static void event_reset(Event *event) {
	ResetEvent(event->handle);
}

static int event_wait(Event *event, uint32_t timeout) { // in msec
	return WaitForSingleObject(event->handle, timeout) == WAIT_OBJECT_0 ? 0 : -1;
}

#else

static void event_create(Event *event) {
	pthread_mutex_init(&event->mutex, NULL);
	pthread_cond_init(&event->condition, NULL);

	event->flag = false;
}

static void event_destroy(Event *event) {
	pthread_mutex_destroy(&event->mutex);
	pthread_cond_destroy(&event->condition);
}

static void event_set(Event *event) {
	pthread_mutex_lock(&event->mutex);

	event->flag = true;

	pthread_cond_broadcast(&event->condition);
	pthread_mutex_unlock(&event->mutex);
}

static void event_reset(Event *event) {
	pthread_mutex_lock(&event->mutex);

	event->flag = false;

	pthread_mutex_unlock(&event->mutex);
}

static int event_wait(Event *event, uint32_t timeout) { // in msec
	struct timeval tp;
	struct timespec ts;
	int ret = E_OK;

	gettimeofday(&tp, NULL);

	ts.tv_sec = tp.tv_sec + timeout / 1000;
	ts.tv_nsec = (tp.tv_usec + (timeout % 1000) * 1000) * 1000;

	while (ts.tv_nsec >= 1000000000L) {
		ts.tv_sec += 1;
		ts.tv_nsec -= 1000000000L;
	}

	pthread_mutex_lock(&event->mutex);

	while (!event->flag) {
		ret = pthread_cond_timedwait(&event->condition, &event->mutex, &ts);

		if (ret != 0) {
			ret = E_TIMEOUT;
			break;
		}
	}

	pthread_mutex_unlock(&event->mutex);

	return ret;
}

#endif

/*****************************************************************************
 *
 *                                 Table
 *
 *****************************************************************************/

static void table_create(Table *table) {
	mutex_create(&table->mutex);

	table->used = 0;
	table->allocated = 16;
	table->keys = (uint32_t *)malloc(sizeof(uint32_t) * table->allocated);
	table->values = (void **)malloc(sizeof(void *) * table->allocated);
}

static void table_destroy(Table *table) {
	free(table->keys);
	free(table->values);

	mutex_destroy(&table->mutex);
}

static void table_insert(Table *table, uint32_t key, void *value) {
	int i;

	mutex_lock(&table->mutex);

	for (i = 0; i < table->used; ++i) {
		if (table->keys[i] == key) {
			table->values[i] = value;

			mutex_unlock(&table->mutex);

			return;
		}
	}

	if (table->allocated <= table->used) {
		table->allocated += 16;
		table->keys = (uint32_t *)realloc(table->keys, sizeof(uint32_t) * table->allocated);
		table->values = (void **)realloc(table->values, sizeof(void *) * table->allocated);
	}

	table->keys[table->used] = key;
	table->values[table->used] = value;

	++table->used;

	mutex_unlock(&table->mutex);
}

static void table_remove(Table *table, uint32_t key) {
	int i;
	int tail;

	mutex_lock(&table->mutex);

	for (i = 0; i < table->used; ++i) {
		if (table->keys[i] == key) {
			tail = table->used - i - 1;

			if (tail > 0) {
				memmove(table->keys + i, table->keys + i + 1, sizeof(uint32_t) * tail);
				memmove(table->values + i, table->values + i + 1, sizeof(void *) * tail);
			}

			--table->used;

			break;
		}
	}

	mutex_unlock(&table->mutex);
}

static void *table_get(Table *table, uint32_t key) {
	int i;
	void *value = NULL;

	mutex_lock(&table->mutex);

	for (i = 0; i < table->used; ++i) {
		if (table->keys[i] == key) {
			value = table->values[i];

			break;
		}
	}

	mutex_unlock(&table->mutex);

	return value;
}

/*****************************************************************************
 *
 *                                 Queue
 *
 *****************************************************************************/

enum {
	QUEUE_KIND_EXIT = 0,
	QUEUE_KIND_META,
	QUEUE_KIND_PACKET
};

typedef struct {
	uint8_t function_id;
	uint8_t parameter;
	uint64_t socket_id;
} Meta;

static void queue_create(Queue *queue) {
	queue->head = NULL;
	queue->tail = NULL;

	mutex_create(&queue->mutex);
	semaphore_create(&queue->semaphore);
}

static void queue_destroy(Queue *queue) {
	QueueItem *item = queue->head;
	QueueItem *next;

	while (item != NULL) {
		next = item->next;

		free(item->data);
		free(item);

		item = next;
	}

	mutex_destroy(&queue->mutex);
	semaphore_destroy(&queue->semaphore);
}

static void queue_put(Queue *queue, int kind, void *data) {
	QueueItem *item = (QueueItem *)malloc(sizeof(QueueItem));

	item->next = NULL;
	item->kind = kind;
	item->data = data;

	mutex_lock(&queue->mutex);

	if (queue->tail == NULL) {
		queue->head = item;
		queue->tail = item;
	} else {
		queue->tail->next = item;
		queue->tail = item;
	}

	mutex_unlock(&queue->mutex);
	semaphore_release(&queue->semaphore);
}

static int queue_get(Queue *queue, int *kind, void **data) {
	QueueItem *item;

	if (semaphore_acquire(&queue->semaphore) < 0) {
		return -1;
	}

	mutex_lock(&queue->mutex);

	if (queue->head == NULL) {
		mutex_unlock(&queue->mutex);

		return -1;
	}

	item = queue->head;
	queue->head = item->next;
	item->next = NULL;

	if (queue->tail == item) {
		queue->head = NULL;
		queue->tail = NULL;
	}

	mutex_unlock(&queue->mutex);

	*kind = item->kind;
	*data = item->data;

	free(item);

	return 0;
}

/*****************************************************************************
 *
 *                                 Device
 *
 *****************************************************************************/

enum {
	IPCON_FUNCTION_ENUMERATE = 254
};

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

/*****************************************************************************
 *
 *                                 Brick Daemon
 *
 *****************************************************************************/

enum {
	BRICK_DAEMON_FUNCTION_GET_AUTHENTICATION_NONCE = 1,
	BRICK_DAEMON_FUNCTION_AUTHENTICATE = 2
};

static void brickd_create(BrickDaemon *brickd, const char *uid, IPConnection *ipcon) {
	DevicePrivate *device_p;

	device_create(brickd, uid, ipcon->p, 2, 0, 0);

	device_p = brickd->p;

	device_p->response_expected[BRICK_DAEMON_FUNCTION_GET_AUTHENTICATION_NONCE] = DEVICE_RESPONSE_EXPECTED_ALWAYS_TRUE;
	device_p->response_expected[BRICK_DAEMON_FUNCTION_AUTHENTICATE] = DEVICE_RESPONSE_EXPECTED_TRUE;
}

static void brickd_destroy(BrickDaemon *brickd) {
	device_release(brickd->p);
}

static int brickd_get_authentication_nonce(BrickDaemon *brickd, uint8_t ret_server_nonce[4]) {
	DevicePrivate *device_p = brickd->p;
	GetAuthenticationNonce request;
	GetAuthenticationNonceResponse response;
	int ret;

	ret = packet_header_create(&request.header, sizeof(request), BRICK_DAEMON_FUNCTION_GET_AUTHENTICATION_NONCE, device_p->ipcon_p, device_p);

	if (ret < 0) {
		return ret;
	}

	ret = device_send_request(device_p, (Packet *)&request, (Packet *)&response);

	if (ret < 0) {
		return ret;
	}

	memcpy(ret_server_nonce, response.server_nonce, 4 * sizeof(uint8_t));

	return ret;
}

static int brickd_authenticate(BrickDaemon *brickd, uint8_t client_nonce[4], uint8_t digest[20]) {
	DevicePrivate *device_p = brickd->p;
	Authenticate request;
	int ret;

	ret = packet_header_create(&request.header, sizeof(request), BRICK_DAEMON_FUNCTION_AUTHENTICATE, device_p->ipcon_p, device_p);

	if (ret < 0) {
		return ret;
	}

	memcpy(request.client_nonce, client_nonce, 4 * sizeof(uint8_t));
	memcpy(request.digest, digest, 20 * sizeof(uint8_t));

	ret = device_send_request(device_p, (Packet *)&request, NULL);

	return ret;
}

/*****************************************************************************
 *
 *                                 IPConnection
 *
 *****************************************************************************/

struct _CallbackContext {
	IPConnectionPrivate *ipcon_p;
	Queue queue;
	Thread thread;
	Mutex mutex;
	bool packet_dispatch_allowed;
};

static int ipcon_connect_unlocked(IPConnectionPrivate *ipcon_p, bool is_auto_reconnect);
static void ipcon_disconnect_unlocked(IPConnectionPrivate *ipcon_p);

static DevicePrivate *ipcon_acquire_device(IPConnectionPrivate *ipcon_p, uint32_t uid) {
	DevicePrivate *device_p;

	mutex_lock(&ipcon_p->devices_ref_mutex);

	device_p = (DevicePrivate *)table_get(&ipcon_p->devices, uid);

	if (device_p != NULL) {
		++device_p->ref_count;
	}

	mutex_unlock(&ipcon_p->devices_ref_mutex);

	return device_p;
}

static void ipcon_dispatch_meta(IPConnectionPrivate *ipcon_p, Meta *meta) {
	ConnectedCallbackFunction connected_callback_function;
	DisconnectedCallbackFunction disconnected_callback_function;
	void *user_data;
	bool retry;

	if (meta->function_id == IPCON_CALLBACK_CONNECTED) {
		if (ipcon_p->registered_callbacks[IPCON_CALLBACK_CONNECTED] != NULL) {
			*(void **)(&connected_callback_function) = ipcon_p->registered_callbacks[IPCON_CALLBACK_CONNECTED];
			user_data = ipcon_p->registered_callback_user_data[IPCON_CALLBACK_CONNECTED];

			connected_callback_function(meta->parameter, user_data);
		}
	} else if (meta->function_id == IPCON_CALLBACK_DISCONNECTED) {
		// need to do this here, the receive loop is not allowed to
		// hold the socket mutex because this could cause a deadlock
		// with a concurrent call to the (dis-)connect function
		if (meta->parameter != IPCON_DISCONNECT_REASON_REQUEST) {
			mutex_lock(&ipcon_p->socket_mutex);

			// don't close the socket if it got disconnected or
			// reconnected in the meantime
			if (ipcon_p->socket != NULL && ipcon_p->socket_id == meta->socket_id) {
				// destroy disconnect probe thread
				event_set(&ipcon_p->disconnect_probe_event);
				thread_join(&ipcon_p->disconnect_probe_thread);
				thread_destroy(&ipcon_p->disconnect_probe_thread);

				// destroy socket
				socket_destroy(ipcon_p->socket);
				free(ipcon_p->socket);
				ipcon_p->socket = NULL;
			}

			mutex_unlock(&ipcon_p->socket_mutex);
		}

		// FIXME: wait a moment here, otherwise the next connect
		// attempt will succeed, even if there is no open server
		// socket. the first receive will then fail directly
		thread_sleep(100);

		if (ipcon_p->registered_callbacks[IPCON_CALLBACK_DISCONNECTED] != NULL) {
			*(void **)(&disconnected_callback_function) = ipcon_p->registered_callbacks[IPCON_CALLBACK_DISCONNECTED];
			user_data = ipcon_p->registered_callback_user_data[IPCON_CALLBACK_DISCONNECTED];

			disconnected_callback_function(meta->parameter, user_data);
		}

		if (meta->parameter != IPCON_DISCONNECT_REASON_REQUEST &&
			ipcon_p->auto_reconnect && ipcon_p->auto_reconnect_allowed) {
			ipcon_p->auto_reconnect_pending = true;
			retry = true;

			// block here until reconnect. this is okay, there is no
			// callback to deliver when there is no connection
			while (retry) {
				retry = false;

				mutex_lock(&ipcon_p->socket_mutex);

				if (ipcon_p->auto_reconnect_allowed && ipcon_p->socket == NULL) {
					if (ipcon_connect_unlocked(ipcon_p, true) < 0) {
						retry = true;
					}
				} else {
					ipcon_p->auto_reconnect_pending = false;
				}

				mutex_unlock(&ipcon_p->socket_mutex);

				if (retry) {
					// wait a moment to give another thread a chance to
					// interrupt the auto-reconnect
					thread_sleep(100);
				}
			}
		}
	}
}

static void ipcon_dispatch_packet(IPConnectionPrivate *ipcon_p, Packet *packet) {
	EnumerateCallbackFunction enumerate_callback_function;
	void *user_data;
	EnumerateCallback *enumerate_callback;
	DevicePrivate *device_p;
	CallbackWrapperFunction callback_wrapper_function;

	if (packet->header.function_id == IPCON_CALLBACK_ENUMERATE) {
		if (ipcon_p->registered_callbacks[IPCON_CALLBACK_ENUMERATE] != NULL) {
			*(void **)(&enumerate_callback_function) = ipcon_p->registered_callbacks[IPCON_CALLBACK_ENUMERATE];
			user_data = ipcon_p->registered_callback_user_data[IPCON_CALLBACK_ENUMERATE];
			enumerate_callback = (EnumerateCallback *)packet;

			enumerate_callback_function(enumerate_callback->uid,
			                            enumerate_callback->connected_uid,
			                            enumerate_callback->position,
			                            enumerate_callback->hardware_version,
			                            enumerate_callback->firmware_version,
			                            leconvert_uint16_from(enumerate_callback->device_identifier),
			                            enumerate_callback->enumeration_type,
			                            user_data);
		}
	} else {
		device_p = ipcon_acquire_device(ipcon_p, packet->header.uid);

		if (device_p == NULL) {
			return;
		}

		callback_wrapper_function = device_p->callback_wrappers[packet->header.function_id];

		if (callback_wrapper_function == NULL) {
			device_release(device_p);

			return;
		}

		callback_wrapper_function(device_p, packet);

		device_release(device_p);
	}
}

static void ipcon_callback_loop(void *opaque) {
	CallbackContext *callback = (CallbackContext *)opaque;
	int kind;
	void *data;

	while (true) {
		if (queue_get(&callback->queue, &kind, &data) < 0) {
			// FIXME: what to do here? try again? exit?
			break;
		}

		// FIXME: cannot lock callback mutex here because this can
		//        deadlock due to an ordering problem with the socket mutex
		//mutex_lock(&callback->mutex);

		if (kind == QUEUE_KIND_EXIT) {
			//mutex_unlock(&callback->mutex);
			break;
		} else if (kind == QUEUE_KIND_META) {
			ipcon_dispatch_meta(callback->ipcon_p, (Meta *)data);
		} else if (kind == QUEUE_KIND_PACKET) {
			// don't dispatch callbacks when the receive thread isn't running
			if (callback->packet_dispatch_allowed) {
				ipcon_dispatch_packet(callback->ipcon_p, (Packet *)data);
			}
		}

		//mutex_unlock(&callback->mutex);

		free(data);
	}

	// cleanup
	mutex_destroy(&callback->mutex);
	queue_destroy(&callback->queue);
	thread_destroy(&callback->thread);

	free(callback);
}

// NOTE: assumes that socket_mutex is locked if disconnect_immediately is true
static void ipcon_handle_disconnect_by_peer(IPConnectionPrivate *ipcon_p,
                                            uint8_t disconnect_reason,
                                            uint64_t socket_id,
                                            bool disconnect_immediately) {
	Meta *meta;

	ipcon_p->auto_reconnect_allowed = true;

	if (disconnect_immediately) {
		ipcon_disconnect_unlocked(ipcon_p);
	}

	meta = (Meta *)malloc(sizeof(Meta));
	meta->function_id = IPCON_CALLBACK_DISCONNECTED;
	meta->parameter = disconnect_reason;
	meta->socket_id = socket_id;

	queue_put(&ipcon_p->callback->queue, QUEUE_KIND_META, meta);
}

enum {
	IPCON_DISCONNECT_PROBE_INTERVAL = 5000
};

enum {
	IPCON_FUNCTION_DISCONNECT_PROBE = 128
};

// NOTE: the disconnect probe loop is not allowed to hold the socket_mutex at any
//       time because it is created and joined while the socket_mutex is locked
static void ipcon_disconnect_probe_loop(void *opaque) {
	IPConnectionPrivate *ipcon_p = (IPConnectionPrivate *)opaque;
	PacketHeader disconnect_probe;

	packet_header_create(&disconnect_probe, sizeof(PacketHeader),
	                     IPCON_FUNCTION_DISCONNECT_PROBE, ipcon_p, NULL);

	while (event_wait(&ipcon_p->disconnect_probe_event,
	                  IPCON_DISCONNECT_PROBE_INTERVAL) < 0) {
		if (ipcon_p->disconnect_probe_flag) {
			// FIXME: this might block
			if (socket_send(ipcon_p->socket, &disconnect_probe,
			                disconnect_probe.length) < 0) {
				ipcon_handle_disconnect_by_peer(ipcon_p, IPCON_DISCONNECT_REASON_ERROR,
				                                ipcon_p->socket_id, false);
				break;
			}
		} else {
			ipcon_p->disconnect_probe_flag = true;
		}
	}
}

static void ipcon_handle_response(IPConnectionPrivate *ipcon_p, Packet *response) {
	DevicePrivate *device_p;
	uint8_t sequence_number = packet_header_get_sequence_number(&response->header);
	Packet *callback;

	ipcon_p->disconnect_probe_flag = false;

	response->header.uid = leconvert_uint32_from(response->header.uid);

	if (sequence_number == 0 &&
	    response->header.function_id == IPCON_CALLBACK_ENUMERATE) {
		if (ipcon_p->registered_callbacks[IPCON_CALLBACK_ENUMERATE] != NULL) {
			callback = (Packet *)malloc(response->header.length);

			memcpy(callback, response, response->header.length);
			queue_put(&ipcon_p->callback->queue, QUEUE_KIND_PACKET, callback);
		}

		return;
	}

	device_p = ipcon_acquire_device(ipcon_p, response->header.uid);

	if (device_p == NULL) {
		// ignoring response for an unknown device
		return;
	}

	if (sequence_number == 0) {
		if (device_p->registered_callbacks[response->header.function_id] != NULL) {
			callback = (Packet *)malloc(response->header.length);

			memcpy(callback, response, response->header.length);
			queue_put(&ipcon_p->callback->queue, QUEUE_KIND_PACKET, callback);
		}

		device_release(device_p);

		return;
	}

	if (device_p->expected_response_function_id == response->header.function_id &&
	    device_p->expected_response_sequence_number == sequence_number) {
		mutex_lock(&device_p->response_mutex);
		memcpy(&device_p->response_packet, response, response->header.length);
		mutex_unlock(&device_p->response_mutex);

		event_set(&device_p->response_event);

		device_release(device_p);

		return;
	}

	device_release(device_p);

	// response seems to be OK, but can't be handled
}

// NOTE: the receive loop is now allowed to hold the socket_mutex at any time
//       because it is created and joined while the socket_mutex is locked
static void ipcon_receive_loop(void *opaque) {
	IPConnectionPrivate *ipcon_p = (IPConnectionPrivate *)opaque;
	uint64_t socket_id = ipcon_p->socket_id;
	Packet pending_data[10];
	int pending_length = 0;
	int length;
	uint8_t disconnect_reason;

	while (ipcon_p->receive_flag) {
		length = socket_receive(ipcon_p->socket, (uint8_t *)pending_data + pending_length,
		                        sizeof(pending_data) - pending_length);

		if (!ipcon_p->receive_flag) {
			return;
		}

		if (length <= 0) {
			if (length < 0 && errno == EINTR) {
				continue;
			}

			if (length == 0) {
				disconnect_reason = IPCON_DISCONNECT_REASON_SHUTDOWN;
			} else {
				disconnect_reason = IPCON_DISCONNECT_REASON_ERROR;
			}

			ipcon_handle_disconnect_by_peer(ipcon_p, disconnect_reason, socket_id, false);
			return;
		}

		pending_length += length;

		while (ipcon_p->receive_flag) {
			if (pending_length < 8) {
				// wait for complete header
				break;
			}

			length = pending_data[0].header.length;

			if (pending_length < length) {
				// wait for complete packet
				break;
			}

			ipcon_handle_response(ipcon_p, pending_data);

			memmove(pending_data, (uint8_t *)pending_data + length,
			        pending_length - length);
			pending_length -= length;
		}
	}
}

// NOTE: assumes that socket_mutex is locked
static int ipcon_connect_unlocked(IPConnectionPrivate *ipcon_p, bool is_auto_reconnect) {
	struct hostent *entity;
	struct sockaddr_in address;
	uint8_t connect_reason;
	Meta *meta;

	// create callback queue and thread
	if (ipcon_p->callback == NULL) {
		ipcon_p->callback = (CallbackContext *)malloc(sizeof(CallbackContext));

		ipcon_p->callback->ipcon_p = ipcon_p;
		ipcon_p->callback->packet_dispatch_allowed = false;

		queue_create(&ipcon_p->callback->queue);
		mutex_create(&ipcon_p->callback->mutex);

		if (thread_create(&ipcon_p->callback->thread, ipcon_callback_loop,
		                  ipcon_p->callback) < 0) {
			mutex_destroy(&ipcon_p->callback->mutex);
			queue_destroy(&ipcon_p->callback->queue);

			free(ipcon_p->callback);
			ipcon_p->callback = NULL;

			return E_NO_THREAD;
		}
	}

	// create and connect socket
	entity = gethostbyname(ipcon_p->host);

	if (entity == NULL) {
		// destroy callback thread
		if (!is_auto_reconnect) {
			queue_put(&ipcon_p->callback->queue, QUEUE_KIND_EXIT, NULL);

			if (!thread_is_current(&ipcon_p->callback->thread)) {
				thread_join(&ipcon_p->callback->thread);
			}

			ipcon_p->callback = NULL;
		}

		return E_HOSTNAME_INVALID;
	}

	memset(&address, 0, sizeof(struct sockaddr_in));
	memcpy(&address.sin_addr, entity->h_addr_list[0], entity->h_length);

	address.sin_family = AF_INET;
	address.sin_port = htons(ipcon_p->port);

	ipcon_p->socket = (Socket *)malloc(sizeof(Socket));

	if (socket_create(ipcon_p->socket, AF_INET, SOCK_STREAM, 0) < 0) {
		// destroy callback thread
		if (!is_auto_reconnect) {
			queue_put(&ipcon_p->callback->queue, QUEUE_KIND_EXIT, NULL);

			if (!thread_is_current(&ipcon_p->callback->thread)) {
				thread_join(&ipcon_p->callback->thread);
			}

			ipcon_p->callback = NULL;
		}

		// destroy socket
		free(ipcon_p->socket);
		ipcon_p->socket = NULL;

		return E_NO_STREAM_SOCKET;
	}

	if (socket_connect(ipcon_p->socket, &address, sizeof(address)) < 0) {
		// destroy callback thread
		if (!is_auto_reconnect) {
			queue_put(&ipcon_p->callback->queue, QUEUE_KIND_EXIT, NULL);

			if (!thread_is_current(&ipcon_p->callback->thread)) {
				thread_join(&ipcon_p->callback->thread);
			}

			ipcon_p->callback = NULL;
		}

		// destroy socket
		socket_destroy(ipcon_p->socket);
		free(ipcon_p->socket);
		ipcon_p->socket = NULL;

		return E_NO_CONNECT;
	}

	++ipcon_p->socket_id;

	// create disconnect probe thread
	ipcon_p->disconnect_probe_flag = true;

	event_reset(&ipcon_p->disconnect_probe_event);

	if (thread_create(&ipcon_p->disconnect_probe_thread,
	                  ipcon_disconnect_probe_loop, ipcon_p) < 0) {
		// destroy callback thread
		if (!is_auto_reconnect) {
			queue_put(&ipcon_p->callback->queue, QUEUE_KIND_EXIT, NULL);

			if (!thread_is_current(&ipcon_p->callback->thread)) {
				thread_join(&ipcon_p->callback->thread);
			}

			ipcon_p->callback = NULL;
		}

		// destroy socket
		socket_destroy(ipcon_p->socket);
		free(ipcon_p->socket);
		ipcon_p->socket = NULL;

		return E_NO_THREAD;
	}

	// create receive thread
	ipcon_p->receive_flag = true;
	ipcon_p->callback->packet_dispatch_allowed = true;

	if (thread_create(&ipcon_p->receive_thread, ipcon_receive_loop, ipcon_p) < 0) {
		// destroy socket
		ipcon_disconnect_unlocked(ipcon_p);

		// destroy callback thread
		if (!is_auto_reconnect) {
			queue_put(&ipcon_p->callback->queue, QUEUE_KIND_EXIT, NULL);

			if (!thread_is_current(&ipcon_p->callback->thread)) {
				thread_join(&ipcon_p->callback->thread);
			}

			ipcon_p->callback = NULL;
		}

		return E_NO_THREAD;
	}

	ipcon_p->auto_reconnect_allowed = false;
	ipcon_p->auto_reconnect_pending = false;

	// trigger connected callback
	if (is_auto_reconnect) {
		connect_reason = IPCON_CONNECT_REASON_AUTO_RECONNECT;
	} else {
		connect_reason = IPCON_CONNECT_REASON_REQUEST;
	}

	meta = (Meta *)malloc(sizeof(Meta));
	meta->function_id = IPCON_CALLBACK_CONNECTED;
	meta->parameter = connect_reason;
	meta->socket_id = 0;

	queue_put(&ipcon_p->callback->queue, QUEUE_KIND_META, meta);

	return E_OK;
}

// NOTE: assumes that socket_mutex is locked
static void ipcon_disconnect_unlocked(IPConnectionPrivate *ipcon_p) {
	// destroy disconnect probe thread
	event_set(&ipcon_p->disconnect_probe_event);
	thread_join(&ipcon_p->disconnect_probe_thread);
	thread_destroy(&ipcon_p->disconnect_probe_thread);

	// stop dispatching packet callbacks before ending the receive
	// thread to avoid timeout exceptions due to callback functions
	// trying to call getters
	if (!thread_is_current(&ipcon_p->callback->thread)) {
		// FIXME: cannot lock callback mutex here because this can
		//        deadlock due to an ordering problem with the socket mutex
		//mutex_lock(&ipcon->callback->mutex);

		ipcon_p->callback->packet_dispatch_allowed = false;

		//mutex_unlock(&ipcon->callback->mutex);
	} else {
		ipcon_p->callback->packet_dispatch_allowed = false;
	}

	// destroy receive thread
	if (ipcon_p->receive_flag) {
		ipcon_p->receive_flag = false;

		socket_shutdown(ipcon_p->socket);

		thread_join(&ipcon_p->receive_thread);
		thread_destroy(&ipcon_p->receive_thread);
	}

	// destroy socket
	socket_destroy(ipcon_p->socket);
	free(ipcon_p->socket);
	ipcon_p->socket = NULL;
}

static int ipcon_send_request(IPConnectionPrivate *ipcon_p, Packet *request) {
	int ret = E_OK;

	mutex_lock(&ipcon_p->socket_mutex);

	if (ipcon_p->socket == NULL) {
		ret = E_NOT_CONNECTED;
	}

	if (ret == E_OK) {
		if (socket_send(ipcon_p->socket, request, request->header.length) < 0) {
			ipcon_handle_disconnect_by_peer(ipcon_p, IPCON_DISCONNECT_REASON_ERROR,
			                                0, true);

			ret = E_NOT_CONNECTED;
		} else {
			ipcon_p->disconnect_probe_flag = false;
		}
	}

	mutex_unlock(&ipcon_p->socket_mutex);

	return ret;
}

void ipcon_create(IPConnection *ipcon) {
	IPConnectionPrivate *ipcon_p;
	int i;

	ipcon_p = (IPConnectionPrivate *)malloc(sizeof(IPConnectionPrivate));
	ipcon->p = ipcon_p;

#ifdef _WIN32
	ipcon_p->wsa_startup_done = false;
#endif

	ipcon_p->host = NULL;
	ipcon_p->port = 0;

	ipcon_p->timeout = 2500;

	ipcon_p->auto_reconnect = true;
	ipcon_p->auto_reconnect_allowed = false;
	ipcon_p->auto_reconnect_pending = false;

	mutex_create(&ipcon_p->sequence_number_mutex);
	ipcon_p->next_sequence_number = 0;

	mutex_create(&ipcon_p->authentication_mutex);
	ipcon_p->next_authentication_nonce = 0;

	mutex_create(&ipcon_p->devices_ref_mutex);
	table_create(&ipcon_p->devices);

	for (i = 0; i < IPCON_NUM_CALLBACK_IDS; ++i) {
		ipcon_p->registered_callbacks[i] = NULL;
		ipcon_p->registered_callback_user_data[i] = NULL;
	}

	mutex_create(&ipcon_p->socket_mutex);
	ipcon_p->socket = NULL;
	ipcon_p->socket_id = 0;

	ipcon_p->receive_flag = false;

	ipcon_p->callback = NULL;

	ipcon_p->disconnect_probe_flag = false;
	event_create(&ipcon_p->disconnect_probe_event);

	semaphore_create(&ipcon_p->wait);

	brickd_create(&ipcon_p->brickd, "2", ipcon);
}

void ipcon_destroy(IPConnection *ipcon) {
	IPConnectionPrivate *ipcon_p = ipcon->p;

	ipcon_disconnect(ipcon); // FIXME: disable disconnected callback before?

	brickd_destroy(&ipcon_p->brickd);

	mutex_destroy(&ipcon_p->authentication_mutex);

	mutex_destroy(&ipcon_p->sequence_number_mutex);

	table_destroy(&ipcon_p->devices); // FIXME: destroy all devices?
	mutex_destroy(&ipcon_p->devices_ref_mutex);

	mutex_destroy(&ipcon_p->socket_mutex);

	event_destroy(&ipcon_p->disconnect_probe_event);

	semaphore_destroy(&ipcon_p->wait);

	free(ipcon_p->host);

	free(ipcon_p);
}

int ipcon_connect(IPConnection *ipcon, const char *host, uint16_t port) {
	IPConnectionPrivate *ipcon_p = ipcon->p;
	int ret;
#ifdef _WIN32
	WSADATA wsa_data;
#endif

	mutex_lock(&ipcon_p->socket_mutex);

#ifdef _WIN32
	if (!ipcon_p->wsa_startup_done) {
		if (WSAStartup(MAKEWORD(2, 2), &wsa_data) != 0) {
			mutex_unlock(&ipcon_p->socket_mutex);

			return E_NO_STREAM_SOCKET;
		}

		ipcon_p->wsa_startup_done = true;
	}
#endif

	if (ipcon_p->socket != NULL) {
		mutex_unlock(&ipcon_p->socket_mutex);

		return E_ALREADY_CONNECTED;
	}

	free(ipcon_p->host);

	ipcon_p->host = strdup(host);
	ipcon_p->port = port;

	ret = ipcon_connect_unlocked(ipcon_p, false);

	mutex_unlock(&ipcon_p->socket_mutex);

	return ret;
}

int ipcon_disconnect(IPConnection *ipcon) {
	IPConnectionPrivate *ipcon_p = ipcon->p;
	CallbackContext *callback;
	Meta *meta;

	mutex_lock(&ipcon_p->socket_mutex);

	ipcon_p->auto_reconnect_allowed = false;

	if (ipcon_p->auto_reconnect_pending) {
		// abort pending auto-reconnect
		ipcon_p->auto_reconnect_pending = false;
	} else {
		if (ipcon_p->socket == NULL) {
			mutex_unlock(&ipcon_p->socket_mutex);

			return E_NOT_CONNECTED;
		}

		ipcon_disconnect_unlocked(ipcon_p);
	}

	// destroy callback thread
	callback = ipcon_p->callback;
	ipcon_p->callback = NULL;

	mutex_unlock(&ipcon_p->socket_mutex);

	// do this outside of socket_mutex to allow calling (dis-)connect from
	// the callbacks while blocking on the join call here
	meta = (Meta *)malloc(sizeof(Meta));
	meta->function_id = IPCON_CALLBACK_DISCONNECTED;
	meta->parameter = IPCON_DISCONNECT_REASON_REQUEST;
	meta->socket_id = 0;

	queue_put(&callback->queue, QUEUE_KIND_META, meta);
	queue_put(&callback->queue, QUEUE_KIND_EXIT, NULL);

	if (!thread_is_current(&callback->thread)) {
		thread_join(&callback->thread);
	}

	// NOTE: no further cleanup of the callback queue and thread here, the
	// callback thread is doing this on exit

	return E_OK;
}

int ipcon_authenticate(IPConnection *ipcon, const char secret[64]) {
	IPConnectionPrivate *ipcon_p = ipcon->p;
	int ret;
	uint32_t nonces[2]; // server, client
	uint8_t digest[SHA1_DIGEST_LENGTH];

	mutex_lock(&ipcon_p->authentication_mutex);

	if (ipcon_p->next_authentication_nonce == 0) {
		ipcon_p->next_authentication_nonce = get_random_uint32();
	}

	ret = brickd_get_authentication_nonce(&ipcon_p->brickd, (uint8_t *)nonces);

	if (ret < 0) {
		mutex_unlock(&ipcon_p->authentication_mutex);

		return ret;
	}

	nonces[1] = ipcon_p->next_authentication_nonce++;

	hmac_sha1((uint8_t *)secret, string_length(secret, IPCON_MAX_SECRET_LENGTH),
	          (uint8_t *)nonces, sizeof(nonces), digest);

	ret = brickd_authenticate(&ipcon_p->brickd, (uint8_t *)&nonces[1], digest);

	if (ret < 0) {
		mutex_unlock(&ipcon_p->authentication_mutex);

		return ret;
	}

	mutex_unlock(&ipcon_p->authentication_mutex);

	return E_OK;
}

int ipcon_get_connection_state(IPConnection *ipcon) {
	IPConnectionPrivate *ipcon_p = ipcon->p;

	if (ipcon_p->socket != NULL) {
		return IPCON_CONNECTION_STATE_CONNECTED;
	} else if (ipcon_p->auto_reconnect_pending) {
		return IPCON_CONNECTION_STATE_PENDING;
	} else {
		return IPCON_CONNECTION_STATE_DISCONNECTED;
	}
}

void ipcon_set_auto_reconnect(IPConnection *ipcon, bool auto_reconnect) {
	IPConnectionPrivate *ipcon_p = ipcon->p;

	ipcon_p->auto_reconnect = auto_reconnect;

	if (!ipcon_p->auto_reconnect) {
		// abort potentially pending auto reconnect
		ipcon_p->auto_reconnect_allowed = false;
	}
}

bool ipcon_get_auto_reconnect(IPConnection *ipcon) {
	return ipcon->p->auto_reconnect;
}

void ipcon_set_timeout(IPConnection *ipcon, uint32_t timeout) { // in msec
	ipcon->p->timeout = timeout;
}

uint32_t ipcon_get_timeout(IPConnection *ipcon) { // in msec
	return ipcon->p->timeout;
}

int ipcon_enumerate(IPConnection *ipcon) {
	IPConnectionPrivate *ipcon_p = ipcon->p;
	Enumerate enumerate;
	int ret;

	ret = packet_header_create(&enumerate.header, sizeof(Enumerate),
	                           IPCON_FUNCTION_ENUMERATE, ipcon_p, NULL);

	if (ret < 0) {
		return ret;
	}

	return ipcon_send_request(ipcon_p, (Packet *)&enumerate);
}

void ipcon_wait(IPConnection *ipcon) {
	semaphore_acquire(&ipcon->p->wait);
}

void ipcon_unwait(IPConnection *ipcon) {
	semaphore_release(&ipcon->p->wait);
}

void ipcon_register_callback(IPConnection *ipcon, uint8_t id, void *callback,
                             void *user_data) {
	IPConnectionPrivate *ipcon_p = ipcon->p;

	ipcon_p->registered_callbacks[id] = callback;
	ipcon_p->registered_callback_user_data[id] = user_data;
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

int16_t leconvert_int16_to(int16_t native) {
	return leconvert_uint16_to(native);
}

uint16_t leconvert_uint16_to(uint16_t native) {
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

#ifdef __cplusplus
}
#endif

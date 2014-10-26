package ipconnection

import (
	"fmt"
	"log"
	"strings"
)

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
 * Possible values for connect_reason parameter of ConnectedCallback.
 */
const (
	IPCON_CONNECT_REASON_REQUEST = 0
	IPCON_CONNECT_REASON_AUTO_RECONNECT = 1
)

/**
 * Possible values for disconnect_reason parameter of DisconnectedCallback.
 */
const (
	IPCON_DISCONNECT_REASON_REQUEST = 0
	IPCON_DISCONNECT_REASON_ERROR = 1
	IPCON_DISCONNECT_REASON_SHUTDOWN = 2
)

/**
 * Possible return values of ipcon_get_connection_state.
 */
const (
	IPCON_CONNECTION_STATE_DISCONNECTED = 0
	IPCON_CONNECTION_STATE_CONNECTED = 1
	IPCON_CONNECTION_STATE_PENDING = 2 // auto-reconnect in progress
	IPCON_NUM_CALLBACK_IDS = 256
	IPCON_MAX_SECRET_LENGTH = 64
)

/**
 * \internal
 */
type IPConnection struct {

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

const (
	IPCON_DISCONNECT_PROBE_INTERVAL = 5000
	IPCON_FUNCTION_DISCONNECT_PROBE = 128
)

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

	mutex_lock(&ipcon_p->socket_mutex);

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


package ipconnetion
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
	"sync"
)

type Event struct {
	// ??? pthread_cond_t condition
	mutex sync.Mutex
	flag bool
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

typedef void (*CallbackWrapperFunction)(DevicePrivate *device_p, Packet *packet);

const (
	DEVICE_NUM_FUNCTION_IDS = 256
)

/**
 * \internal
 */

/**
 * \internal
 */
type Device BrickDaemon;

/*
 * Copyright (C) 2012-2014 Matthias Bolte <matthias@tinkerforge.com>
 * Copyright (C) 2011 Olaf Lüke <olaf@tinkerforge.com>
 *
 * Redistribution and use in source and binary forms of this file,
 * with or without modification, are permitted. See the Creative
 * Commons Zero (CC0 1.0) License for more details.
 */

type Enumerate struct {
	header PacketHeader
}

type EnumerateCallback struct {
	PacketHeader header
	char uid[8]
	char connected_uid[8]
	char position
	uint8_t hardware_version[3]
	uint8_t firmware_version[3]
	uint16_t device_identifier
	uint8_t enumeration_type
}

type GetAuthenticationNonce struct {
	PacketHeader header
} GetAuthenticationNonce

type GetAuthenticationNonceResponse struct {
	PacketHeader header
	uint8_t server_nonce[4]
} GetAuthenticationNonceResponse

type Authenticate struct {
	PacketHeader header
	uint8_t client_nonce[4]
	uint8_t digest[20]
} Authenticate

/*****************************************************************************
 *
 *                                 Event
 *
 *****************************************************************************/

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


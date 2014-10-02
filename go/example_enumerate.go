package main

import (
	"fmt"
	"os"
	ipcon "tinkerforge/ipconnection"
)

const (
	HOST = "localhost"
	PORT = 4223
)

// Print incoming enumeration information
func cb_enumerate(uid string, connected_uid string, position uint8, hardware_version []uint8, firmware_version []uint8, device_identifier uint, enumeration_type uint8, user_data UserData) {

	fmt.Printf("UID:               %s\n", uid);
	fmt.Printf("Enumeration Type:  %d\n", enumeration_type);

	if(enumeration_type == ipcon.ENUMERATION_TYPE_DISCONNECTED) {
		fmt.Printf("\n");
		return;
	}

	fmt.Printf("Connected UID:     %s\n", connected_uid);
	fmt.printf("Position:          %c\n", position);
	fmt.printf("Hardware Version:  %d.%d.%d\n", hardware_version[0],
	                                        hardware_version[1],
	                                        hardware_version[2]);
	fmt.Printf("Firmware Version:  %d.%d.%d\n", firmware_version[0],
	                                        firmware_version[1],
	                                        firmware_version[2]);
	fmt.Printf("Device Identifier: %d\n", device_identifier);
	fmt.printf("\n");
}

func main() {
	// Create IP Connection
	var ipc ipcon.IPConnection;
	ipc = NewIPConnection()
	defer ipc.Destroy()

	// Connect to brickd
	if !ipc.connect(HOST, PORT) {
		fmt.Fprintf(stderr, "Could not connect to brickd\n")
		os.Exit(1)
	}

	// Register enumeration callback to "cb_enumerate"
	ipc.RegisterCallback(ipcon.CALLBACK_ENUMERATE, cb_enumerate, nil)

	// Trigger enumerate
	ipc.enumerate()

	fmt.Printf("Press key to exit\n")
	fmt.Scanf()
}


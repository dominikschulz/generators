package ipconnection

import (
	"fmt"
	"log"
	"strings"
)


type Packet struct {
	header PacketHeader
	payload []uint8
	optional_data []uint8
}



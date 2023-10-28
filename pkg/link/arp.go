package link

import (
    "encoding/binary"
    "net/netip"
    "bytes"
)

const (
    HARDWARE_TYPE  = 1 // 2 bytes (ethernet)
    PROTOCOL_TYPE  = 0x0800 // 2 bytes (ipv4)
    HLEN = 6 // IPv4 + port (6 bytes), 1 byte
    PLEN = 4 // IPv4, 1 byte
    ARP_REQUEST = 1 // 2 bytes
    ARP_REPLY = 2 // 2 bytes

    ARP_TO = 3
)

type ARPEntry struct {
    // Represents a single entry in ARP Cache
    IPAddress netip.Addr
    MACAddress netip.AddrPort
}

type ARPMessage struct {
    HardwareType uint16
    ProtocolType uint16
    // sz of hardware address
    HardwareLen uint8
    // sz of protocol address
    ProtocolLen uint8
    // req or reply
    Operation uint16
    // Sender
    SHA [HLEN]byte
    SPA [PLEN]byte
    // Target
    THA [HLEN]byte
    TPA [PLEN]byte
}

// Check if this packet is an arp message given a byte slice
func IsThisARPPacket(b []byte) bool {
    // first two bytes should be hardware type 
    // the next two bytes should be protocol type
    hardwareType := binary.BigEndian.Uint16(b[0:2])
    protocolType := binary.BigEndian.Uint16(b[2:4])
    return hardwareType == HARDWARE_TYPE && protocolType == PROTOCOL_TYPE
}

// Unmarshal arp frame into ARPMessage struct
func UnMarshalARPFrame(b []byte) ARPMessage {
    return ARPMessage{
        HardwareType: binary.BigEndian.Uint16(b[0:2]),
        ProtocolType: binary.BigEndian.Uint16(b[2:4]),
        HardwareLen: uint8(b[4]),
        ProtocolLen: uint8(b[5]),
        Operation: binary.BigEndian.Uint16(b[6:8]),
        SHA: [HLEN]byte(b[8:14]),
        SPA: [PLEN]byte(b[14:18]),
        THA: [HLEN]byte(b[18:24]),
        TPA: [PLEN]byte(b[24:28]),
    }
}

// Create ARP Frame
// - sha -> Sender Hardware Address
// - spa -> Sender Protocol Address
// - tha -> Target Hardware Address
// - tpa -> Target Protocol Address
// - arpType -> either ARP_REQUEST or ARP_REPLY
// returns the frame payload or error
func CreateARPFrame(sha [6]byte, spa [4]byte, tha [6]byte, tpa [4]byte, arpType uint16) ([]byte, error) {
    buf := new(bytes.Buffer)
    // Hardware Type
    err := binary.Write(buf, binary.BigEndian, uint16(HARDWARE_TYPE))
    if err != nil {
        return nil, err
    }
    // Protocol Type
    err = binary.Write(buf, binary.BigEndian, uint16(PROTOCOL_TYPE))
    if err != nil {
        return nil, err
    }
    // Hardware Length
    err = binary.Write(buf, binary.BigEndian, uint8(HLEN))
    if err != nil {
        return nil, err
    }
    // Protocol Length
    err = binary.Write(buf, binary.BigEndian, uint8(PLEN))
    if err != nil {
        return nil, err
    }
    // Operation
    err = binary.Write(buf, binary.BigEndian, uint16(arpType))
    if err != nil {
        return nil, err
    }
    // Sender Hardware Address
    _, err = buf.Write(sha[:])
    if err != nil {
        return nil, err
    }
    // Sender Protocol Address
    _, err = buf.Write(spa[:])
    if err != nil {
        return nil, err
    }
    // Target Hardware Address
    _, err = buf.Write(tha[:])
    if err != nil {
        return nil, err
    }
    // Target Protocol Address
    _, err = buf.Write(tpa[:])
    if err != nil {
        return nil, err
    }
    return buf.Bytes(), nil
}
package layers

import (
	"encoding/binary"
	"errors"

	"github.com/google/gopacket"
)

// BNCSProtocol defines which protocol is being used
type BNCSProtocol uint8

// BNCSProtocol known values.
const (
	BNCSUnset         BNCSProtocol = 0x00
	BNCSGameProtocol  BNCSProtocol = 0x01
	BNCSBNFTPProtocol BNCSProtocol = 0x02
)

// String shows the BNCS protocol in a human readable format
func (bncsp BNCSProtocol) String() string {
	switch bncsp {
	default:
		return "Unknown"
	case BNCSGameProtocol:
		return "Game Protocl"
	case BNCSBNFTPProtocol:
		return "BNFTP Protocol"
	}
}

const (
	BNCSHeaderFixed uint8 = 0xff
)

// BNCSMessageID represents a BNCS Message by ID
type BNCSMessageID uint8

// BNCS is the Battle.Net Chat Server protocol
// See https://bnetdocs.org/document/10/battle-net-chat-server-protocol-overview
// for more information.
type BNCS struct {
	BaseLayer

	protocol BNCSProtocol // which protocol are we looking at
}

// BNCSHeader contains all information for BNCS messages
type BNCSHeader struct {
	Fixed         uint8 // Always 0xff
	MessageID     BNCSMessageID
	MessageLength uint16 // Message length including header
	Data          []byte
}

// LayerType returns gopacket.LayerTypeBNCS
func (bncs *BNCS) LayerType() gopacket.LayerType { return LayerTypeBNCS }

// decodeBNCS decodes the byte slice into a BNCS type.
func decodeBNCS(data []byte, p gopacket.PacketBuilder) error {
	bncs := &BNCS{}
	err := bncs.DecodeFromBytes(data, p)
	if err != nil {
		return err
	}
	p.AddLayer(bncs)
	p.SetApplicationLayer(bncs)
	return nil
}

// DecodeFromBytes decodes the slice into the BNCS struct
func (bncs *BNCS) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	bncs.BaseLayer.Contents = data
	bncs.BaseLayer.Payload = nil

	return bncs.decodeBNCSPackets(data, df)
}

func (bncs *BNCS) decodeBNCSPackets(data []byte, df gopacket.DecodeFeedback) error {
	if bncs.protocol == BNCSUnset && len(data) == 1 {
		bncs.protocol = BNCSProtocol(data[0])
		if bncs.protocol.String() == "Unknown" {
			return errors.New("Unknown BNCS protocol")
		}
		bncs.BaseLayer = BaseLayer{Contents: data[:1]}
		return nil
	}

	bncs.BaseLayer = BaseLayer{Contents: data[:len(data)]}

	var h BNCSHeader
	h.Fixed = data[0]
	h.MessageID = BNCSMessageID(data[2])
	h.MessageLength = binary.LittleEndian.Uint16(data[3:5])
	copy(h.Data, data[5:])

	if h.Fixed != BNCSHeaderFixed {
		return errors.New("Invalid BNCS header, fixed value mismatch")
	}

	if len(data) < int(h.MessageLength) {
		df.SetTruncated()
		return errors.New("BNCS packet length mismatch")
	}

	if len(data) == int(data[2]) {
		return nil
	}
	return nil
}

// CanDecode implements gopacket.DecodingLayer
func (bncs *BNCS) CanDecode() gopacket.LayerClass {
	return LayerTypeBNCS
}

// NextLayerType implements gopacket.DecodingLayer
func (bncs *BNCS) NextLayerType() gopacket.LayerType {
	return gopacket.LayerTypeZero
}

// Payload returns nil because its in the header data
func (bncs *BNCS) Payload() []byte {
	return nil
}

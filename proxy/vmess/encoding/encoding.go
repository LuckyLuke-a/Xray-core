package encoding

import (
	"github.com/luckyluke-a/xray-core/common/net"
	"github.com/luckyluke-a/xray-core/common/protocol"
)

//go:generate go run github.com/luckyluke-a/xray-core/common/errors/errorgen

const (
	Version = byte(1)
)

var addrParser = protocol.NewAddressParser(
	protocol.AddressFamilyByte(byte(protocol.AddressTypeIPv4), net.AddressFamilyIPv4),
	protocol.AddressFamilyByte(byte(protocol.AddressTypeDomain), net.AddressFamilyDomain),
	protocol.AddressFamilyByte(byte(protocol.AddressTypeIPv6), net.AddressFamilyIPv6),
	protocol.PortThenAddress(),
)

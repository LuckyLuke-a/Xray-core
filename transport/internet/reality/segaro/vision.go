package segaro

import (
	"bytes"
	"fmt"
	"math/rand"
	"net"
	"reflect"
	"strconv"
	"strings"
	"time"
	"unsafe"

	"github.com/luckyluke-a/xray-core/common/buf"
	"github.com/luckyluke-a/xray-core/common/errors"
	"github.com/luckyluke-a/xray-core/proxy"
	"github.com/luckyluke-a/xray-core/transport/internet/grpc/encoding"
	"github.com/luckyluke-a/xray-core/transport/internet/reality"
	"github.com/luckyluke-a/xray-core/transport/internet/stat"

	goReality "github.com/LuckyLuke-a/reality"
)

type SegaroConfig struct {
	RealityConfig   *reality.Config
	GoRealityConfig *goReality.Config
}

func (sc *SegaroConfig) GetPaddingSize() uint32 {
	if sc.RealityConfig != nil {
		return sc.RealityConfig.PaddingSize
	}
	return sc.GoRealityConfig.PaddingSize
}

func (sc *SegaroConfig) GetSubChunkSize() uint32 {
	if sc.RealityConfig != nil {
		return sc.RealityConfig.SubchunkSize
	}
	return sc.GoRealityConfig.SubChunkSize
}

func (sc *SegaroConfig) GetServerRandPacketSize() (int, int) {
	var randomPacket string
	if sc.RealityConfig != nil {
		randomPacket = sc.RealityConfig.ServerRandPacket
	} else {
		randomPacket = sc.GoRealityConfig.ServerRandPacket
	}
	randPacket := strings.Split(randomPacket, "-")
	if len(randPacket) == 0 {
		return 0, 0
	}
	min, _ := strconv.Atoi(randPacket[0])
	if len(randPacket) == 1 {
		return min, min
	}
	max, _ := strconv.Atoi(randPacket[1])
	return min, max
}

func (sc *SegaroConfig) GetClientRandPacketSize() (int, int) {
	var randomPacket string
	if sc.RealityConfig != nil {
		randomPacket = sc.RealityConfig.ClientRandPacket
	} else {
		randomPacket = sc.GoRealityConfig.ClientRandPacket
	}
	randPacket := strings.Split(randomPacket, "-")
	if len(randPacket) == 0 {
		return 0, 0
	}
	min, _ := strconv.Atoi(randPacket[0])
	if len(randPacket) == 1 {
		return min, min
	}
	max, _ := strconv.Atoi(randPacket[1])
	return min, max
}

func (sc *SegaroConfig) GetServerRandPacketCount() (int, int) {
	var randomPacketCount string
	if sc.RealityConfig != nil {
		randomPacketCount = sc.RealityConfig.ServerRandPacketCount
	} else {
		randomPacketCount = sc.GoRealityConfig.ServerRandPacketCount
	}
	randPacket := strings.Split(randomPacketCount, "-")
	if len(randPacket) == 0 {
		return 0, 0
	}
	min, _ := strconv.Atoi(randPacket[0])
	if len(randPacket) == 1 {
		return min, min
	}
	max, _ := strconv.Atoi(randPacket[1])
	return min, max
}

func (sc *SegaroConfig) GetClientRandPacketCount() (int, int) {
	var randomPacketCount string
	if sc.RealityConfig != nil {
		randomPacketCount = sc.RealityConfig.ClientRandPacketCount
	} else {
		randomPacketCount = sc.GoRealityConfig.ClientRandPacketCount
	}
	randPacket := strings.Split(randomPacketCount, "-")
	if len(randPacket) == 0 {
		return 0, 0
	}
	min, _ := strconv.Atoi(randPacket[0])
	if len(randPacket) == 1 {
		return min, min
	}
	max, _ := strconv.Atoi(randPacket[1])
	return min, max
}

func (sc *SegaroConfig) GetSplitSize() (int, int) {
	var splitPacket string
	if sc.RealityConfig != nil {
		splitPacket = sc.RealityConfig.SplitPacket
	} else {
		splitPacket = sc.GoRealityConfig.SplitPacket
	}
	splitedPacket := strings.Split(splitPacket, "-")
	if len(splitedPacket) == 0 {
		return 0, 0
	}
	min, _ := strconv.Atoi(splitedPacket[0])
	if len(splitedPacket) == 1 {
		return min, min
	}
	max, _ := strconv.Atoi(splitedPacket[1])
	return min, max
}

// GetPrivateField, returns the private fieldName from v object
func GetPrivateField(v interface{}, fieldName string) (interface{}, error) {
	rv := reflect.ValueOf(v)

	// If the value is not addressable, make a copy that is addressable
	if !rv.CanAddr() {
		rs := reflect.New(rv.Type()).Elem()
		rs.Set(rv)
		rv = rs
	}

	if rv.Kind() == reflect.Ptr {
		rv = rv.Elem()
	}
	if rv.Kind() != reflect.Struct {
		return nil, errors.New(fmt.Sprintf("expected struct, got %v", rv.Kind()))
	}

	rt := rv.Type()
	structField, ok := rt.FieldByName(fieldName)
	if !ok {
		return nil, errors.New(fmt.Sprintf("field %s not found", fieldName))
	}
	fieldPtr := unsafe.Pointer(rv.UnsafeAddr() + structField.Offset)
	fieldValue := reflect.NewAt(structField.Type, fieldPtr).Elem()
	return fieldValue.Interface(), nil
}

// Send the multiple fake packet
func sendMultipleFakePacket(authKey []byte, useConn *net.Conn, useWriter *buf.Writer, clientTime *time.Time, minRandSize, maxRandSize, minRandCount, maxRandCount int, sendHeader bool) error {
	if maxRandCount == 0 || maxRandSize == 0 || minRandCount == 0 || minRandSize == 0 {
		return nil
	}
	var fakePackets buf.MultiBuffer

	// Calculate fake packet count
	countFakePacket := rand.Intn(maxRandCount-minRandCount+1) + minRandCount
	for counter := 0; counter < countFakePacket; counter++ {
		fakePacketBuff := buf.New()

		// Calculate fake packet length
		randLength := rand.Intn(maxRandSize-minRandSize+1) + minRandSize

		// Calculate packet validation time (It doesn't matter if this var value is too low or too high, we just want random numbers, meaning the server and client can generate the same value)
		timeInterval := int64(((counter + 1) * randLength) + minRandSize)

		// Generate random packet
		generateRandomPacket(fakePacketBuff, authKey, timeInterval, randLength, clientTime)

		// Add fake packet length to the first of it
		if _, err := fakePacketBuff.WriteAtBeginning([]byte{byte(fakePacketBuff.Len() >> 8), byte(fakePacketBuff.Len())}); err != nil {
			return err
		}

		// Add to multibuffer
		fakePackets = append(fakePackets, fakePacketBuff)
	}

	// Add all fake packets length to the first packet
	if _, err := fakePackets[0].WriteAtBeginning([]byte{byte(fakePackets.Len() >> 8), byte(fakePackets.Len())}); err != nil {
		return err
	}

	if sendHeader {
		if _, err := fakePackets[0].WriteAtBeginning([]byte{
			0, // Vless header request version
			0, // Vless header vision
		}); err != nil {
			return err
		}
	}

	if useWriter != nil {
		err := (*useWriter).WriteMultiBuffer(fakePackets)
		if err != nil {
			return err
		}
	} else {
		for _, packet := range fakePackets {
			_, err := (*useConn).Write(packet.Bytes())
			if err != nil {
				return err
			}
			packet.Release()
			packet = nil
		}
	}

	fakePackets = nil
	return nil
}

// isFakePacketsValid, checks the received fake packets is valid or not
func isFakePacketsValid(multiBuff *buf.MultiBuffer, authKey []byte, clientTime *time.Time, minRandSize int) error {
	if (*multiBuff).IsEmpty() {
		return errors.New("fake packets can not be empty!")
	}
	fakePacketBuff := buf.New()
	for counter, b := range *multiBuff {
		fakePacketBuff.Clear()
		timeInterval := int64(((counter + 1) * int(b.Len())) + minRandSize)
		generateRandomPacket(fakePacketBuff, authKey, timeInterval, minRandSize, clientTime)
		if b.Len() < int32(minRandSize) || !bytes.Equal(b.BytesTo(int32(minRandSize)), fakePacketBuff.Bytes()) {
			return errors.New("fake packets incorrect!")
		}
	}
	// Free the memory
	fakePacketBuff.Release()
	fakePacketBuff = nil
	return nil
}

func isHandshakeMessage(message []byte) bool {
	if bytes.HasPrefix(message, proxy.TlsClientHandShakeStart) || bytes.HasPrefix(message, proxy.TlsServerHandShakeStart) || bytes.HasPrefix(message, proxy.TlsChangeCipherSpecStart) {
		return true
	}
	return false
}

// getRealityAuthkey return the authKey and clientTime from conn (h2, grpc, tcp conn supported)
func getRealityAuthkey(conn *net.Conn, fromInbound bool) (authKey []byte, clientTime *time.Time, err error) {
	statConn, ok := (*conn).(*stat.CounterConnection)
	if ok {
		*conn = statConn.Connection
	}

	if fromInbound {
		// tcp
		realityConn, ok := (*conn).(*reality.Conn)
		if ok {
			authKey = realityConn.AuthKey
			clientTime = &realityConn.ClientTime
			return
		}

		var realityServerConn *goReality.Conn
		realityServerConn, err = getRealityServerConn(conn)
		if err != nil {
			return
		}
		authKey = realityServerConn.AuthKey
		clientTime = &realityServerConn.ClientTime

	} else {
		var realityUConn *reality.UConn
		realityUConn, err = getRealityClientConn(conn)
		if err != nil {
			return
		}
		authKey = realityUConn.AuthKey
		clientTime = &realityUConn.ClientTime
	}

	return
}

// GetRealityServerConfig, returns the server config, (tcp, h2, grpc supported)
func GetRealityServerConfig(conn *net.Conn) (config *goReality.Config, err error) {
	var realityConf interface{}
	statConn, ok := (*conn).(*stat.CounterConnection)
	if ok {
		*conn = statConn.Connection
	}

	serverConn, ok := (*conn).(*reality.Conn)
	if ok {
		realityConf = serverConn.Conn
	} else {
		realityConf, err = getRealityServerConn(conn)
	}

	if err != nil {
		return
	}
	realityConf, err = GetPrivateField(realityConf, "config")
	if err != nil {
		return
	}
	config, ok = realityConf.(*goReality.Config)
	if !ok {
		err = errors.New("can not get goReality.Config")
		return
	}
	return
}

// getRealityServerConn, return (h2, grpc) server conn
func getRealityServerConn(conn *net.Conn) (realityConn *goReality.Conn, err error) {
	var connType interface{}
	// buf.BufferedReader
	connType, err = GetPrivateField(*conn, "reader")
	if err != nil {
		return
	}
	// buf.SingleReader
	connType, err = GetPrivateField(connType, "Reader")
	if err != nil {
		return
	}
	_, ok := connType.(*encoding.HunkReaderWriter)
	if ok {
		// grpc
		// encoding.gRPCServiceTunServer
		connType, err = GetPrivateField(connType, "hc")
		if err != nil {
			return
		}
		// grpc.serverStream
		connType, err = GetPrivateField(connType, "ServerStream")
		if err != nil {
			return
		}
		// transport.http2Server
		connType, err = GetPrivateField(connType, "t")
		if err != nil {
			return
		}
		// reality.Conn
		connType, err = GetPrivateField(connType, "conn")
		if err != nil {
			return
		}

	} else {
		// h2
		// http2.requestBody
		connType, err = GetPrivateField(connType, "Reader")
		if err != nil {
			return
		}
		// http2.serverConn
		connType, err = GetPrivateField(connType, "conn")
		if err != nil {
			return
		}
		// h2c.bufConn
		connType, err = GetPrivateField(connType, "conn")
		if err != nil {
			return
		}
		// reality.Conn
		connType, err = GetPrivateField(connType, "Conn")
		if err != nil {
			return
		}
	}

	realityConn, ok = connType.(*goReality.Conn)
	if !ok {
		err = errors.New("failed to get RealityServerConn")
	}
	return
}

// getRealityClientConn, return (h2, grpc) client UConn
func getRealityClientConn(conn *net.Conn) (realityUConn *reality.UConn, err error) {
	var ok bool
	// tcp
	realityUConn, ok = (*conn).(*reality.UConn)
	if ok {
		return
	}

	var connType interface{}

	// buf.BufferedReader
	connType, err = GetPrivateField(*conn, "reader")
	if err != nil {
		return
	}
	// buf.SingleReader
	connType, err = GetPrivateField(connType, "Reader")
	if err != nil {
		return
	}
	_, ok = connType.(*encoding.HunkReaderWriter)
	if ok {
		// grpc
		// encoding.gRPCServiceTunClient
		connType, err = GetPrivateField(connType, "hc")
		if err != nil {
			return
		}
		// grpc.clientStream
		connType, err = GetPrivateField(connType, "ClientStream")
		if err != nil {
			return
		}
		// grpc.csAttempt
		connType, err = GetPrivateField(connType, "attempt")
		if err != nil {
			return
		}
		// transport.http2Client
		connType, err = GetPrivateField(connType, "t")
		if err != nil {
			return
		}
		// reality.UConn
		connType, err = GetPrivateField(connType, "conn")
		if err != nil {
			return
		}

	} else {
		// h2
		// http.WaitReadCloser
		connType, err = GetPrivateField(connType, "Reader")
		if err != nil {
			return
		}
		// http2.transportResponseBody
		connType, err = GetPrivateField(connType, "ReadCloser")
		if err != nil {
			return
		}
		// http2.clientStream
		connType, err = GetPrivateField(connType, "cs")
		if err != nil {
			return
		}
		// http2.ClientConn
		connType, err = GetPrivateField(connType, "cc")
		if err != nil {
			return
		}
		// reality.UConn
		connType, err = GetPrivateField(connType, "tconn")
		if err != nil {
			return
		}
	}

	realityUConn, ok = connType.(*reality.UConn)
	if !ok {
		err = errors.New("can not get reality UConn")
	}
	return
}

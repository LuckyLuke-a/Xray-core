package outbound

//go:generate go run github.com/luckyluke-a/xray-core/common/errors/errorgen

import (
	"bytes"
	"context"
	gotls "crypto/tls"
	"reflect"
	"time"
	"unsafe"

	utls "github.com/LuckyLuke-a/utls"
	proxymanOutbound "github.com/luckyluke-a/xray-core/app/proxyman/outbound"
	"github.com/luckyluke-a/xray-core/common"
	"github.com/luckyluke-a/xray-core/common/buf"
	"github.com/luckyluke-a/xray-core/common/errors"
	"github.com/luckyluke-a/xray-core/common/net"
	"github.com/luckyluke-a/xray-core/common/protocol"
	"github.com/luckyluke-a/xray-core/common/retry"
	"github.com/luckyluke-a/xray-core/common/session"
	"github.com/luckyluke-a/xray-core/common/signal"
	"github.com/luckyluke-a/xray-core/common/task"
	"github.com/luckyluke-a/xray-core/common/xudp"
	"github.com/luckyluke-a/xray-core/core"
	"github.com/luckyluke-a/xray-core/features/policy"
	"github.com/luckyluke-a/xray-core/proxy"
	"github.com/luckyluke-a/xray-core/proxy/vless"
	"github.com/luckyluke-a/xray-core/proxy/vless/encoding"
	"github.com/luckyluke-a/xray-core/transport"
	"github.com/luckyluke-a/xray-core/transport/internet"
	"github.com/luckyluke-a/xray-core/transport/internet/reality"
	"github.com/luckyluke-a/xray-core/transport/internet/reality/segaro"
	"github.com/luckyluke-a/xray-core/transport/internet/stat"
	"github.com/luckyluke-a/xray-core/transport/internet/tls"
)

func init() {
	common.Must(common.RegisterConfig((*Config)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return New(ctx, config.(*Config))
	}))
}

// Handler is an outbound connection handler for VLess protocol.
type Handler struct {
	serverList    *protocol.ServerList
	serverPicker  protocol.ServerPicker
	policyManager policy.Manager
	cone          bool
}

// New creates a new VLess outbound handler.
func New(ctx context.Context, config *Config) (*Handler, error) {
	serverList := protocol.NewServerList()
	for _, rec := range config.Vnext {
		s, err := protocol.NewServerSpecFromPB(rec)
		if err != nil {
			return nil, errors.New("failed to parse server spec").Base(err).AtError()
		}
		serverList.AddServer(s)
	}

	v := core.MustFromContext(ctx)
	handler := &Handler{
		serverList:    serverList,
		serverPicker:  protocol.NewRoundRobinServerPicker(serverList),
		policyManager: v.GetFeature(policy.ManagerType()).(policy.Manager),
		cone:          ctx.Value("cone").(bool),
	}

	return handler, nil
}

// Process implements proxy.Outbound.Process().
func (h *Handler) Process(ctx context.Context, link *transport.Link, dialer internet.Dialer) error {
	outbounds := session.OutboundsFromContext(ctx)
	ob := outbounds[len(outbounds)-1]
	if !ob.Target.IsValid() {
		return errors.New("target not specified").AtError()
	}
	ob.Name = "vless"

	var rec *protocol.ServerSpec
	var conn stat.Connection
	if err := retry.ExponentialBackoff(5, 200).On(func() error {
		rec = h.serverPicker.PickServer()
		var err error
		conn, err = dialer.Dial(ctx, rec.Destination())
		if err != nil {
			return err
		}
		return nil
	}); err != nil {
		return errors.New("failed to find an available destination").Base(err).AtWarning()
	}
	defer conn.Close()

	iConn := conn
	if statConn, ok := iConn.(*stat.CounterConnection); ok {
		iConn = statConn.Connection
	}
	target := ob.Target
	errors.LogInfo(ctx, "tunneling request to ", target, " via ", rec.Destination().NetAddr())

	command := protocol.RequestCommandTCP
	if target.Network == net.Network_UDP {
		command = protocol.RequestCommandUDP
	}
	if target.Address.Family().IsDomain() && target.Address.Domain() == "v1.mux.cool" {
		command = protocol.RequestCommandMux
	}

	request := &protocol.RequestHeader{
		Version: encoding.Version,
		User:    rec.PickUser(),
		Command: command,
		Address: target.Address,
		Port:    target.Port,
	}

	account := request.User.Account.(*vless.MemoryAccount)

	requestAddons := &encoding.Addons{
		Flow: account.Flow,
	}

	var segaroConfig *segaro.SegaroConfig
	var input *bytes.Reader
	var rawInput *bytes.Buffer
	var xsvCanContinue chan bool
	allowUDP443 := false
	switch requestAddons.Flow {
	case vless.XRV + "-udp443":
		allowUDP443 = true
		requestAddons.Flow = requestAddons.Flow[:16]
		fallthrough
	case vless.XRV:
		ob.CanSpliceCopy = 2
		switch request.Command {
		case protocol.RequestCommandUDP:
			if !allowUDP443 && request.Port == 443 {
				return errors.New("XTLS rejected UDP/443 traffic").AtInfo()
			}
		case protocol.RequestCommandMux:
			fallthrough // let server break Mux connections that contain TCP requests
		case protocol.RequestCommandTCP:
			var t reflect.Type
			var p uintptr
			if tlsConn, ok := iConn.(*tls.Conn); ok {
				t = reflect.TypeOf(tlsConn.Conn).Elem()
				p = uintptr(unsafe.Pointer(tlsConn.Conn))
			} else if utlsConn, ok := iConn.(*tls.UConn); ok {
				t = reflect.TypeOf(utlsConn.Conn).Elem()
				p = uintptr(unsafe.Pointer(utlsConn.Conn))
			} else if realityConn, ok := iConn.(*reality.UConn); ok {
				t = reflect.TypeOf(realityConn.Conn).Elem()
				p = uintptr(unsafe.Pointer(realityConn.Conn))
			} else {
				return errors.New("XTLS only supports TLS and REALITY directly for now.").AtWarning()
			}
			i, _ := t.FieldByName("input")
			r, _ := t.FieldByName("rawInput")
			input = (*bytes.Reader)(unsafe.Pointer(p + i.Offset))
			rawInput = (*bytes.Buffer)(unsafe.Pointer(p + r.Offset))
		}
	case vless.XSV + "-udp443":
		allowUDP443 = true
		requestAddons.Flow = requestAddons.Flow[:18]
		fallthrough
	case vless.XSV:
		ob.CanSpliceCopy = 3
		switch request.Command {
		case protocol.RequestCommandUDP:
			if !allowUDP443 && request.Port == 443 {
				return errors.New("XTLS rejected UDP/443 traffic").AtInfo()
			}
		}
		outboundHandler, ok := dialer.(*proxymanOutbound.Handler)
		if !ok {
			return errors.New("failed to get reality proxymanOutbound.Handler")
		}
		streamSettings, err := segaro.GetPrivateField(outboundHandler, "streamSettings")
		if err != nil {
			return errors.New("failed to get reality streamSettings")
		}
		memoryStreamConfig, ok := streamSettings.(*internet.MemoryStreamConfig)
		if !ok {
			return errors.New("failed to get reality memoryStreamConfig")
		}
		realityConfig := reality.ConfigFromStreamSettings(memoryStreamConfig)
		if realityConfig == nil {
			return errors.New("failed to get reality ConfigFromStreamSettings")
		}
		segaroConfig = &segaro.SegaroConfig{RealityConfig: realityConfig, NumberOfTLSPacketToFilter: 3}
		xsvCanContinue = make(chan bool, 1)

	default:
		ob.CanSpliceCopy = 3
	}

	var newCtx context.Context
	var newCancel context.CancelFunc
	if session.TimeoutOnlyFromContext(ctx) {
		newCtx, newCancel = context.WithCancel(context.Background())
	}

	sessionPolicy := h.policyManager.ForLevel(request.User.Level)
	ctx, cancel := context.WithCancel(ctx)
	timer := signal.CancelAfterInactivity(ctx, func() {
		cancel()
		if newCancel != nil {
			newCancel()
		}
	}, sessionPolicy.Timeouts.ConnectionIdle)

	clientReader := link.Reader // .(*pipe.Reader)
	clientWriter := link.Writer // .(*pipe.Writer)
	trafficState := proxy.NewTrafficState(account.ID.Bytes())
	if request.Command == protocol.RequestCommandUDP && (requestAddons.Flow == vless.XRV || (h.cone && request.Port != 53 && request.Port != 443)) {
		request.Command = protocol.RequestCommandMux
		request.Address = net.DomainAddress("v1.mux.cool")
		request.Port = net.Port(666)
	}

	postRequest := func() error {
		defer timer.SetTimeout(sessionPolicy.Timeouts.DownlinkOnly)

		bufferWriter := buf.NewBufferedWriter(buf.NewWriter(conn))
		if err := encoding.EncodeRequestHeader(bufferWriter, request, requestAddons); err != nil {
			return errors.New("failed to encode request header").Base(err).AtWarning()
		}

		// default: serverWriter := bufferWriter
		serverWriter := encoding.EncodeBodyAddons(bufferWriter, request, requestAddons, trafficState, ctx, segaroConfig, conn)
		if request.Command == protocol.RequestCommandMux && request.Port == 666 {
			serverWriter = xudp.NewPacketWriter(serverWriter, target, xudp.GetGlobalID(ctx))
		}
		timeoutReader, ok := clientReader.(buf.TimeoutReader)
		if ok {
			multiBuffer, err1 := timeoutReader.ReadMultiBufferTimeout(time.Millisecond * 500)
			if err1 == nil {
				if err := serverWriter.WriteMultiBuffer(multiBuffer); err != nil {
					return err // ...
				}
			} else if err1 != buf.ErrReadTimeout {
				return err1
			} else if requestAddons.Flow == vless.XRV {
				mb := make(buf.MultiBuffer, 1)
				errors.LogInfo(ctx, "Insert padding with empty content to camouflage VLESS header ", mb.Len())
				if err := serverWriter.WriteMultiBuffer(mb); err != nil {
					return err // ...
				}
			} else if requestAddons.Flow == vless.XSV {
				mb := buf.MultiBuffer{buf.New()}
				serverWriter.WriteMultiBuffer(mb)
			}
		} else {
			errors.LogDebug(ctx, "Reader is not timeout reader, will send out vless header separately from first payload")
		}
		// Flush; bufferWriter.WriteMultiBuffer now is bufferWriter.writer.WriteMultiBuffer
		if err := bufferWriter.SetBuffered(false); err != nil {
			return errors.New("failed to write A request payload").Base(err).AtWarning()
		}

		var err error
		switch requestAddons.Flow {
		case vless.XRV:
			if tlsConn, ok := iConn.(*tls.Conn); ok {
				if tlsConn.ConnectionState().Version != gotls.VersionTLS13 {
					return errors.New(`failed to use `+requestAddons.Flow+`, found outer tls version `, tlsConn.ConnectionState().Version).AtWarning()
				}
			} else if utlsConn, ok := iConn.(*tls.UConn); ok {
				if utlsConn.ConnectionState().Version != utls.VersionTLS13 {
					return errors.New(`failed to use `+requestAddons.Flow+`, found outer tls version `, utlsConn.ConnectionState().Version).AtWarning()
				}
			}
			ctx1 := session.ContextWithInbound(ctx, nil) // TODO enable splice
			err = encoding.XtlsWrite(clientReader, serverWriter, timer, conn, trafficState, ob, ctx1)
		case vless.XSV:
			err = segaro.SegaroWrite(clientReader, serverWriter, timer, conn, false, segaroConfig, xsvCanContinue)
		default:
			// from clientReader.ReadMultiBuffer to serverWriter.WriteMultiBuffer
			err = buf.Copy(clientReader, serverWriter, buf.UpdateActivity(timer))
		}
		if err != nil {
			return errors.New("failed to transfer request payload").Base(err).AtInfo()
		}

		// Indicates the end of request payload.
		switch requestAddons.Flow {
		default:
		}
		return nil
	}

	getResponse := func() error {
		defer timer.SetTimeout(sessionPolicy.Timeouts.UplinkOnly)

		var err error
		if _, err = encoding.DecodeResponseHeader(conn, request); err != nil {
			return errors.New("failed to decode response header").Base(err).AtInfo()
		}

		// default: serverReader := buf.NewReader(conn)
		serverReader := encoding.DecodeBodyAddons(conn, request, requestAddons)

		switch requestAddons.Flow {
		case vless.XRV:
			serverReader = proxy.NewVisionReader(serverReader, trafficState, ctx)
		case vless.XSV:
			serverReader = segaro.NewSegaroReader(serverReader)
		}
		if request.Command == protocol.RequestCommandMux && request.Port == 666 {
			if requestAddons.Flow == vless.XRV {
				serverReader = xudp.NewPacketReader(&buf.BufferedReader{Reader: serverReader})
			} else {
				serverReader = xudp.NewPacketReader(conn)
			}
		}

		switch requestAddons.Flow {
		case vless.XRV:
			err = encoding.XtlsRead(serverReader, clientWriter, timer, conn, input, rawInput, trafficState, ob, ctx)
		case vless.XSV:
			err = segaro.SegaroRead(serverReader, clientWriter, timer, conn, false, segaroConfig, xsvCanContinue)
		default:
			// from serverReader.ReadMultiBuffer to clientWriter.WriteMultiBuffer
			err = buf.Copy(serverReader, clientWriter, buf.UpdateActivity(timer))
		}

		if err != nil {
			return errors.New("failed to transfer response payload").Base(err).AtInfo()
		}

		return nil
	}

	if newCtx != nil {
		ctx = newCtx
	}

	if err := task.Run(ctx, postRequest, task.OnSuccess(getResponse, task.Close(clientWriter))); err != nil {
		return errors.New("connection ends").Base(err).AtInfo()
	}

	return nil
}

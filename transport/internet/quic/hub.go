package quic

import (
	"context"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/logging"
	"github.com/quic-go/quic-go/qlog"
	"github.com/luckyluke-a/xray-core/common"
	"github.com/luckyluke-a/xray-core/common/errors"
	"github.com/luckyluke-a/xray-core/common/net"
	"github.com/luckyluke-a/xray-core/common/protocol/tls/cert"
	"github.com/luckyluke-a/xray-core/common/signal/done"
	"github.com/luckyluke-a/xray-core/transport/internet"
	"github.com/luckyluke-a/xray-core/transport/internet/tls"
)

// Listener is an internet.Listener that listens for TCP connections.
type Listener struct {
	rawConn  *sysConn
	listener *quic.Listener
	done     *done.Instance
	addConn  internet.ConnHandler
}

func (l *Listener) acceptStreams(conn quic.Connection) {
	for {
		stream, err := conn.AcceptStream(context.Background())
		if err != nil {
			errors.LogInfoInner(context.Background(), err, "failed to accept stream")
			select {
			case <-conn.Context().Done():
				return
			case <-l.done.Wait():
				if err := conn.CloseWithError(0, ""); err != nil {
					errors.LogInfoInner(context.Background(), err, "failed to close connection")
				}
				return
			default:
				time.Sleep(time.Second)
				continue
			}
		}

		conn := &interConn{
			stream: stream,
			local:  conn.LocalAddr(),
			remote: conn.RemoteAddr(),
		}

		l.addConn(conn)
	}
}

func (l *Listener) keepAccepting() {
	for {
		conn, err := l.listener.Accept(context.Background())
		if err != nil {
			errors.LogInfoInner(context.Background(), err, "failed to accept QUIC connection")
			if l.done.Done() {
				break
			}
			time.Sleep(time.Second)
			continue
		}
		go l.acceptStreams(conn)
	}
}

// Addr implements internet.Listener.Addr.
func (l *Listener) Addr() net.Addr {
	return l.listener.Addr()
}

// Close implements internet.Listener.Close.
func (l *Listener) Close() error {
	l.done.Close()
	l.listener.Close()
	l.rawConn.Close()
	return nil
}

// Listen creates a new Listener based on configurations.
func Listen(ctx context.Context, address net.Address, port net.Port, streamSettings *internet.MemoryStreamConfig, handler internet.ConnHandler) (internet.Listener, error) {
	if address.Family().IsDomain() {
		return nil, errors.New("domain address is not allows for listening quic")
	}

	tlsConfig := tls.ConfigFromStreamSettings(streamSettings)
	if tlsConfig == nil {
		tlsConfig = &tls.Config{
			Certificate: []*tls.Certificate{tls.ParseCertificate(cert.MustGenerate(nil, cert.DNSNames(internalDomain), cert.CommonName(internalDomain)))},
		}
	}

	config := streamSettings.ProtocolSettings.(*Config)
	rawConn, err := internet.ListenSystemPacket(context.Background(), &net.UDPAddr{
		IP:   address.IP(),
		Port: int(port),
	}, streamSettings.SocketSettings)
	if err != nil {
		return nil, err
	}

	quicConfig := &quic.Config{
		KeepAlivePeriod:       0,
		HandshakeIdleTimeout:  time.Second * 8,
		MaxIdleTimeout:        time.Second * 300,
		MaxIncomingStreams:    32,
		MaxIncomingUniStreams: -1,
		Tracer: func(ctx context.Context, p logging.Perspective, ci quic.ConnectionID) *logging.ConnectionTracer {
			return qlog.NewConnectionTracer(&QlogWriter{connID: ci}, p, ci)
		},
	}

	conn, err := wrapSysConn(rawConn.(*net.UDPConn), config)
	if err != nil {
		conn.Close()
		return nil, err
	}
	tr := quic.Transport{
		ConnectionIDLength: 12,
		Conn:               conn,
	}
	qListener, err := tr.Listen(tlsConfig.GetTLSConfig(), quicConfig)
	if err != nil {
		conn.Close()
		return nil, err
	}

	listener := &Listener{
		done:     done.New(),
		rawConn:  conn,
		listener: qListener,
		addConn:  handler,
	}

	go listener.keepAccepting()

	return listener, nil
}

func init() {
	common.Must(internet.RegisterTransportListener(protocolName, Listen))
}

package tagged

import (
	"context"

	"github.com/luckyluke-a/xray-core/common/net"
)

type DialFunc func(ctx context.Context, dest net.Destination, tag string) (net.Conn, error)

var Dialer DialFunc

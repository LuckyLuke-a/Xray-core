package udp

import (
	"github.com/luckyluke-a/xray-core/common"
	"github.com/luckyluke-a/xray-core/transport/internet"
)

func init() {
	common.Must(internet.RegisterProtocolConfigCreator(protocolName, func() interface{} {
		return new(Config)
	}))
}

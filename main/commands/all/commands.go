package all

import (
	"github.com/luckyluke-a/xray-core/main/commands/all/api"
	"github.com/luckyluke-a/xray-core/main/commands/all/convert"
	"github.com/luckyluke-a/xray-core/main/commands/all/tls"
	"github.com/luckyluke-a/xray-core/main/commands/base"
)

// go:generate go run github.com/luckyluke-a/xray-core/common/errors/errorgen

func init() {
	base.RootCommand.Commands = append(
		base.RootCommand.Commands,
		api.CmdAPI,
		convert.CmdConvert,
		tls.CmdTLS,
		cmdUUID,
		cmdX25519,
		cmdWG,
	)
}

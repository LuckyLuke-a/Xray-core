package drain

import "io"

//go:generate go run github.com/luckyluke-a/xray-core/common/errors/errorgen

type Drainer interface {
	AcknowledgeReceive(size int)
	Drain(reader io.Reader) error
}

package dns_test

import (
	"context"
	"testing"
	"time"

	. "github.com/luckyluke-a/xray-core/app/dns"
	"github.com/luckyluke-a/xray-core/common"
	"github.com/luckyluke-a/xray-core/common/net"
	"github.com/luckyluke-a/xray-core/features/dns"
)

func TestLocalNameServer(t *testing.T) {
	s := NewLocalNameServer()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*2)
	ips, err := s.QueryIP(ctx, "google.com", net.IP{}, dns.IPOption{
		IPv4Enable: true,
		IPv6Enable: true,
		FakeEnable: false,
	}, false)
	cancel()
	common.Must(err)
	if len(ips) == 0 {
		t.Error("expect some ips, but got 0")
	}
}

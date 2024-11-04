// build +linux
package stun

import (
	"context"
	"fmt"
	"net"
	"testing"

	"github.com/pion/stun"
	"golang.org/x/net/ipv4"
)

func TestStun_New(t *testing.T) {

	udpAddr, err := net.ResolveUDPAddr("udp", ":12333")

	if err != nil {
		t.Error(err)
	}

	conn, err := net.ListenUDP("udp", udpAddr)

	if err != nil {
		t.Error(err)
	}

	defer conn.Close()
	ctx := context.Background()

	s, err := New(ctx, 12222)
	s.Start(ctx)

	if err != nil {
		t.Error(err)
	}

	go func() {
		for {
			buf := make([]byte, 1024)
			n, _, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}

			msg := stun.New()
			msg.Raw = buf[:n]
			msg.Decode()
			fmt.Println("received", msg)

			expectedIP := net.ParseIP("127.0.0.1")
			expectedPort := 21254
			addr := stun.XORMappedAddress{
				IP:   expectedIP,
				Port: expectedPort,
			}

			addr.AddTo(msg)
			buf, _ = msg.GobEncode()

			if n > 0 {
				ipv4Conn := ipv4.NewPacketConn(conn)
				ipv4Conn.WriteTo(buf, nil, &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12222})
				break
			}
		}
	}()

	_, _, err = s.Connect(context.Background(), "127.0.0.1:12333")

	if err != nil {
		t.Error(err)
	}
}

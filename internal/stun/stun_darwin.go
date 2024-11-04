// build +darwin
package stun

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/pion/stun"
	"github.com/rs/zerolog"
	"golang.org/x/net/ipv4"
)

const PacketSize = 1500

type Stun struct {
	port         uint16
	once         sync.Once
	packetChan   chan []byte
	packetSource *gopacket.PacketSource
	handle       *pcap.Handle
	conn         *ipv4.PacketConn
}

func New(ctx context.Context, port uint16) (*Stun, error) {

	c, err := net.ListenPacket("ip4:17", "0.0.0.0")
	if err != nil {
		return nil, err
	}

	conn := ipv4.NewPacketConn(c)

	handle, err := pcap.OpenLive("eth0", 1600, true, pcap.BlockForever)
	if err != nil {
		return nil, err
	}

	err = handle.SetBPFFilter(fmt.Sprintf("udp dst port %d and udp[8:4] = 0x2112A442", port))

	if err != nil {
		return nil, err
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	return &Stun{
		port:         port,
		packetChan:   make(chan []byte),
		packetSource: packetSource,
		handle:       handle,
		conn:         conn,
	}, nil
}

func (s *Stun) Stop() error {
	close(s.packetChan)
	s.handle.Close()
	return s.conn.Close()
}

func (s *Stun) Start(ctx context.Context) {
	s.once.Do(func() {
		go func() {
			for {
				select {
				case <-ctx.Done():
					return
				case <-time.After(time.Duration(StunTimeout+5) * time.Second):
					return
				default:
					buf := make([]byte, PacketSize)
					packet, err := s.packetSource.NextPacket()
					if err != nil {
						continue
					}
					n := copy(buf, packet.Data())
					s.packetChan <- buf[:n]
					return
				}
			}
		}()
	})
}

func (s *Stun) Connect(ctx context.Context, stunAddr string) (_ string, _ int, err error) {
	logger := zerolog.Ctx(ctx)

	logger.Info().Msgf("connecting to STUN server: %s", stunAddr)
	addr, err := net.ResolveUDPAddr("udp4", stunAddr)
	if err != nil {
		return "", 0, err
	}

	packet, err := createStunBindingPacket(s.port, uint16(addr.Port))
	if err != nil {
		return "", 0, err
	}

	_, err = s.conn.WriteTo(packet, nil, addr)
	if err != nil {
		return "", 0, fmt.Errorf("failed to send STUN packet: %w", err)
	}

	reply, err := s.Read(ctx)
	if err != nil {
		return "", 0, err
	}

	replyAddr := Parse(ctx, reply)

	return replyAddr.IP.String(), replyAddr.Port, nil
}

func (s *Stun) Read(ctx context.Context) (*stun.Message, error) {
	select {
	case buf := <-s.packetChan:
		m := &stun.Message{
			Raw: buf[8:],
		}

		if err := m.Decode(); err != nil {
			return nil, err
		}

		return m, nil
	case <-time.After(time.Duration(StunTimeout) * time.Second):
		return nil, ErrTimeout
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func createStunBindingPacket(srcPort, dstPort uint16) ([]byte, error) {
	msg, err := stun.Build(stun.TransactionID, stun.BindingRequest)
	if err != nil {
		return nil, err
	}
	_ = msg.NewTransactionID()

	packetLength := uint16(BindingPacketHeaderSize + len(msg.Raw))
	checksum := uint16(0)

	buf := make([]byte, BindingPacketHeaderSize)
	binary.BigEndian.PutUint16(buf[0:], srcPort)
	binary.BigEndian.PutUint16(buf[2:], dstPort)
	binary.BigEndian.PutUint16(buf[4:], packetLength)
	binary.BigEndian.PutUint16(buf[6:], checksum)

	return append(buf, msg.Raw...), nil
}

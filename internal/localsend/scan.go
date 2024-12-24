package localsend

import (
	"encoding/json"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/0w0mewo/localsend-cli/internal/models"
	"github.com/0w0mewo/localsend-cli/internal/store"
	"github.com/0w0mewo/localsend-cli/internal/utils"
)

const (
	maxAdvCount = 5
	advInterval = 3 * time.Second
)

var multicastDiscoveryAddr = &net.UDPAddr{
	IP:   net.ParseIP("224.0.0.167"),
	Port: 53317,
}

type MulticastAdvertiser struct {
	conn *net.UDPConn
	anno *models.Announcement
	stop chan struct{}
}

func NewMulticastAdvertiser(devInfo models.DeviceInfo, supportHttps bool) (*MulticastAdvertiser, error) {
	conn, err := net.DialUDP("udp", nil, multicastDiscoveryAddr)
	if err != nil {
		return nil, err
	}

	protocol := "http"
	if supportHttps {
		protocol = "https"
	}

	return &MulticastAdvertiser{
		conn: conn,
		anno: &models.Announcement{
			DeviceInfo: devInfo,
			Port:       53317,
			Protocol:   protocol,
			Announce:   true,
		},
		stop: make(chan struct{}),
	}, nil
}

func (ma *MulticastAdvertiser) Start() error {
	ticker := time.NewTicker(advInterval)
	defer ticker.Stop()

	ma.advertise()

	for {
		select {
		case <-ma.stop:
			return nil
		case <-ticker.C:
			err := ma.advertise()
			if err != nil {
				slog.Warn("Fail to send announcement", "error", err)
				continue
			}

		}
	}
}

func (ma *MulticastAdvertiser) advertise() error {
	b, err := json.Marshal(ma.anno)
	if err != nil {
		return err
	}

	_, err = ma.conn.Write(b)
	if err != nil {
		return err
	}

	return nil
}

func (ma *MulticastAdvertiser) Stop() error {
	ma.stop <- struct{}{}
	return ma.conn.Close()
}

type MulticastScanner struct {
	conn    *net.UDPConn
	devices map[string]models.Announcement
	mu      *sync.RWMutex
}

func NewMulticastScanner() (*MulticastScanner, error) {
	conn, err := net.ListenMulticastUDP("udp", nil, multicastDiscoveryAddr)
	if err != nil {
		return nil, err
	}

	return &MulticastScanner{
		conn:    conn,
		devices: make(map[string]models.Announcement),
		mu:      &sync.RWMutex{},
	}, nil
}

func (mcs *MulticastScanner) Scan(timeout time.Duration) error {
	var err error
	for trial := 0; trial < 3; trial++ {
		err = readAndRegister(timeout/3, mcs.conn)
		if err != nil {
			continue
		}
	}
	return err
}

func (mcs *MulticastScanner) Stop() error {
	return mcs.conn.Close()
}

func readAndRegister(timeout time.Duration, conn *net.UDPConn) error {
	conn.SetReadBuffer(512)
	conn.SetDeadline(time.Now().Add(timeout))

	buf := make([]byte, 512)

	n, remoteAddr, err := conn.ReadFromUDP(buf)
	if err != nil {
		return err
	}

	var anno models.Announcement
	err = json.Unmarshal(buf[:n], &anno)
	if err != nil {
		return err
	}

	myIPAddrs, err := utils.GetMyIPv4Addr()
	if err != nil {
		return err
	}

	for idx := range myIPAddrs {
		// avoid self discovery
		if !myIPAddrs[idx].Equal(remoteAddr.IP) {
			store.PutDevice(remoteAddr.IP, anno)
		}
	}

	return nil
}

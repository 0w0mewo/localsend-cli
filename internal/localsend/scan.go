package localsend

import (
	"encoding/json"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/0w0mewo/localsend-cli/internal/models"
	"github.com/0w0mewo/localsend-cli/internal/utils"
)

const (
	advInterval = 3 * time.Second
)

var multicastDiscoveryAddr = &net.UDPAddr{
	IP:   net.ParseIP("224.0.0.167"),
	Port: 53317,
}

type Discoverier struct {
	mcastConn   *net.UDPConn
	selfAnno    *models.Announcement
	discoveried map[string]models.Announcement
	mu          *sync.RWMutex
	stop        chan struct{}
}

func NewDiscoverier(devInfo models.DeviceInfo, supportHttps bool) (*Discoverier, error) {
	conn, err := net.ListenMulticastUDP("udp", nil, multicastDiscoveryAddr)
	if err != nil {
		return nil, err
	}

	protocol := "http"
	if supportHttps {
		protocol = "https"
	}

	return &Discoverier{
		mcastConn: conn,
		selfAnno: &models.Announcement{
			DeviceInfo: devInfo,
			Port:       53317,
			Protocol:   protocol,
			Announce:   true,
		},
		stop:        make(chan struct{}),
		discoveried: make(map[string]models.Announcement),
		mu:          &sync.RWMutex{},
	}, nil
}

func (ma *Discoverier) Listen() error {
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
			err = ma.readAndRegister()
			if err != nil {
				continue
			}
		}
	}
}

func (ma *Discoverier) advertise() error {
	b, err := json.Marshal(ma.selfAnno)
	if err != nil {
		return err
	}

	_, err = ma.mcastConn.WriteToUDP(b, multicastDiscoveryAddr)
	if err != nil {
		return err
	}

	return nil
}

func (ma *Discoverier) Shutdown() error {
	err := ma.mcastConn.Close()
	ma.stop <- struct{}{}
	return err
}

func (mcs *Discoverier) readAndRegister() error {
	mcs.mcastConn.SetReadBuffer(512)
	mcs.mcastConn.SetReadDeadline(time.Now().Add(1 * time.Second))

	buf := make([]byte, 512)

	n, remoteAddr, err := mcs.mcastConn.ReadFromUDP(buf)
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
			mcs.PutDiscovered(remoteAddr.IP.To4().String(), anno)
		}
	}

	return nil
}

func (mcs *Discoverier) GetAllDiscovered() map[string]models.Announcement {
	mcs.mu.RLock()
	defer mcs.mu.RUnlock()

	return mcs.discoveried
}

func (mcs *Discoverier) PutDiscovered(ip string, anno models.Announcement) {
	mcs.mu.Lock()
	defer mcs.mu.Unlock()

	mcs.discoveried[ip] = anno
}

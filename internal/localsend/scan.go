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
	cachedIPs   []net.IP
	ipCacheTime time.Time
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

	conn.SetReadBuffer(512)

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
	// Close connection first to unblock any pending reads in readAndRegister(),
	// allowing Listen() to return to the select and receive the stop signal
	ma.mcastConn.Close()
	ma.stop <- struct{}{}
	return nil
}

func (mcs *Discoverier) getCachedIPs() ([]net.IP, error) {
	if time.Since(mcs.ipCacheTime) > 30*time.Second || mcs.cachedIPs == nil {
		ips, err := utils.GetMyIPv4Addr()
		if err != nil {
			return nil, err
		}
		mcs.cachedIPs = ips
		mcs.ipCacheTime = time.Now()
	}
	return mcs.cachedIPs, nil
}

func (mcs *Discoverier) readAndRegister() error {
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

	myIPAddrs, err := mcs.getCachedIPs()
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

	result := make(map[string]models.Announcement, len(mcs.discoveried))
	for k, v := range mcs.discoveried {
		result[k] = v
	}
	return result
}

func (mcs *Discoverier) PutDiscovered(ip string, anno models.Announcement) {
	mcs.mu.Lock()
	defer mcs.mu.Unlock()

	mcs.discoveried[ip] = anno
}

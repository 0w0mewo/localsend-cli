package localsend

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/0w0mewo/localsend-cli/internal/localsend/constants"
	"github.com/0w0mewo/localsend-cli/internal/models"
	"github.com/0w0mewo/localsend-cli/internal/utils"
	"github.com/gofiber/fiber/v2"
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
		stop:        make(chan struct{}, 1),
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

	// Avoid self discovery using fingerprint per protocol spec Section 2 & 3.1
	if anno.Fingerprint == mcs.selfAnno.Fingerprint {
		return nil
	}

	// Register the discovered device
	mcs.PutDiscovered(remoteAddr.IP.To4().String(), anno)

	// Per protocol spec Section 3.1: respond when we receive an announcement with announce:true
	// First try HTTP POST (primary method), then UDP fallback
	if anno.Announce {
		mcs.sendHTTPResponse(remoteAddr.IP.String(), anno)
		mcs.sendUDPResponse(remoteAddr)
	}

	return nil
}

// sendHTTPResponse sends our device info via HTTP POST to /api/localsend/v2/register
// per protocol spec Section 3.1: "First, an HTTP/TCP request is sent to the origin"
func (mcs *Discoverier) sendHTTPResponse(ip string, anno models.Announcement) {
	// Build the registration request body (same fields as announcement, without announce)
	regBody := models.Announcement{
		DeviceInfo: mcs.selfAnno.DeviceInfo,
		Protocol:   mcs.selfAnno.Protocol,
		Port:       mcs.selfAnno.Port,
		Announce:   false, // Not used in HTTP request per spec
	}

	bodyBytes, err := json.Marshal(regBody)
	if err != nil {
		slog.Debug("Failed to marshal HTTP response body", "error", err)
		return
	}

	// Use the protocol and port from the received announcement
	scheme := anno.Protocol
	if scheme == "" {
		scheme = "http"
	}
	port := anno.Port
	if port == 0 {
		port = 53317
	}

	remoteAddr := fmt.Sprintf("%s:%d", ip, port)

	agent := fiber.AcquireAgent()
	defer fiber.ReleaseAgent(agent)

	req := agent.Request()
	req.URI().SetScheme(scheme)
	req.URI().SetHost(remoteAddr)
	req.URI().SetPath(constants.RegisterPath)
	req.Header.SetMethod(fiber.MethodPost)
	req.Header.SetContentType(fiber.MIMEApplicationJSON)
	req.SetBody(bodyBytes)

	if err := agent.Parse(); err != nil {
		slog.Debug("Failed to parse HTTP register request", "error", err)
		return
	}

	// Skip TLS verification for self-signed certs
	_, _, errs := agent.InsecureSkipVerify().Timeout(2 * time.Second).Bytes()
	if len(errs) > 0 {
		slog.Debug("Failed to send HTTP register response", "remote", remoteAddr, "error", errs[0])
		return
	}

	slog.Debug("Sent HTTP register response", "remote", remoteAddr)
}

// sendUDPResponse sends our device info via UDP as a fallback response
// per protocol spec Section 3.1: "As fallback, members can also respond
// with a Multicast/UDP message" with announce:false
func (mcs *Discoverier) sendUDPResponse(remoteAddr *net.UDPAddr) {
	response := *mcs.selfAnno
	response.Announce = false

	b, err := json.Marshal(response)
	if err != nil {
		slog.Warn("Failed to marshal UDP response", "error", err)
		return
	}

	// Send directly to the remote address (unicast response)
	_, err = mcs.mcastConn.WriteToUDP(b, remoteAddr)
	if err != nil {
		slog.Warn("Failed to send UDP response", "error", err)
	}
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

	// Normalize deviceType per protocol spec Section 7.1
	anno.DeviceType = normalizeDeviceType(anno.DeviceType)
	mcs.discoveried[ip] = anno
}

func (mcs *Discoverier) RegisterDevice(anno models.Announcement) {
	if anno.IP != "" {
		mcs.PutDiscovered(anno.IP, anno)
	}
}

// ScanSubnet performs legacy HTTP discovery by scanning the subnet of all private IPv4 interfaces
// per protocol spec Section 3.2.
func (mcs *Discoverier) ScanSubnet(ctx context.Context) {
	ips, err := mcs.getCachedIPs()
	if err != nil {
		slog.Error("Failed to get local IPs for subnet scan", "error", err)
		return
	}

	var wg sync.WaitGroup
	for _, ip := range ips {
		// Only scan /24 subnets for simplicity and common home network usage
		ipv4 := ip.To4()
		if ipv4 == nil {
			continue
		}

		for i := 1; i < 255; i++ {
			targetIP := net.IPv4(ipv4[0], ipv4[1], ipv4[2], byte(i))
			if targetIP.Equal(ipv4) {
				continue
			}

			wg.Add(1)
			go func(targetIP net.IP) {
				defer wg.Done()
				select {
				case <-ctx.Done():
					return
				default:
					mcs.scanIP(targetIP.String())
				}
			}(targetIP)
		}
	}
	wg.Wait()
}

// httpClientForScan is a shared HTTP client for subnet scanning.
// It's safe for concurrent use and configured with short timeouts.
var httpClientForScan = &http.Client{
	Timeout: 1 * time.Second,
	Transport: &http.Transport{
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
		MaxIdleConnsPerHost: 0, // Don't keep connections open
		DisableKeepAlives:   true,
	},
}

func (mcs *Discoverier) scanIP(ip string) {
	regBody := models.Announcement{
		DeviceInfo: mcs.selfAnno.DeviceInfo,
		Protocol:   mcs.selfAnno.Protocol,
		Port:       mcs.selfAnno.Port,
		Announce:   false,
	}

	bodyBytes, _ := json.Marshal(regBody)
	remoteAddr := net.JoinHostPort(ip, "53317")

	// Try both HTTPS and HTTP as we don't know the receiver's preference
	// Protocol spec 3.2 says to send to all local IP addresses.
	protocols := []string{"https", "http"}
	for _, scheme := range protocols {
		url := fmt.Sprintf("%s://%s%s", scheme, remoteAddr, constants.RegisterPath)

		req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(bodyBytes))
		if err != nil {
			continue
		}
		req.Header.Set("Content-Type", "application/json")

		resp, err := httpClientForScan.Do(req)
		if err != nil {
			continue
		}

		if resp.StatusCode == 200 {
			var deviceInfo models.DeviceInfo
			if err := json.NewDecoder(resp.Body).Decode(&deviceInfo); err == nil {
				deviceInfo.IP = ip
				mcs.PutDiscovered(ip, models.Announcement{
					DeviceInfo: deviceInfo,
					Protocol:   scheme,
					Port:       53317,
					Announce:   false,
				})
				resp.Body.Close()
				return // Found and registered
			}
		}
		resp.Body.Close()
	}
}

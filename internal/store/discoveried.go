package store

import (
	"errors"
	"net"
	"sync"

	"github.com/0w0mewo/localsend-cli/internal/models"
)

var KnownDevices = &discoveriedDevices{
	devices: make(map[string]models.Announcement),
	mu:      &sync.RWMutex{},
}

type discoveriedDevices struct {
	devices map[string]models.Announcement
	mu      *sync.RWMutex
}

var ErrNoSuchDevice = errors.New("No such device")

func PutDevice(ip net.IP, anno models.Announcement) {
	KnownDevices.mu.Lock()
	defer KnownDevices.mu.Unlock()

	anno.IP = ip.To4().String()
	KnownDevices.devices[ip.To4().String()] = anno
}

func GetDevice(ip net.IP) (models.Announcement, error) {
	KnownDevices.mu.RLock()
	defer KnownDevices.mu.RUnlock()

	anno, ok := KnownDevices.devices[ip.To4().String()]
	if !ok {
		return models.Announcement{}, ErrNoSuchDevice
	}

	return anno, nil
}

func GetAllDevices() map[string]models.Announcement {
	KnownDevices.mu.RLock()
	defer KnownDevices.mu.RUnlock()

	return KnownDevices.devices
}

package utils

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"math/rand"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
)

func WaitForSignal() chan os.Signal {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGINT)

	return ch
}

func ForEachAsync[T any](arr []T, wg *sync.WaitGroup, do func(value T)) {
	for _, val := range arr {
		wg.Add(1)
		go func(val T) {
			defer wg.Done()

			do(val)
		}(val)
	}
}

func SHA256ofFile(fpath string) (string, error) {
	fd, err := os.Open(fpath)
	if err != nil {
		return "", err
	}
	defer fd.Close()

	hasher := sha256.New()
	_, err = io.Copy(hasher, fd)
	if err != nil {
		return "", err
	}

	return hex.EncodeToString(hasher.Sum(nil)), nil
}

// getMyIPv4Addr get ipv4 address of every RUNNING interfaces on the host
// Note: ipv6, loopback and non-private addressess are ignored
func GetMyIPv4Addr() ([]net.IP, error) {
	intfs, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	res := make([]net.IP, 0)

	for _, intf := range intfs {
		addrs, _ := intf.Addrs()
		for idx := range addrs {
			ip, _, _ := net.ParseCIDR(addrs[idx].String())
			if ip.To4() != nil && !ip.IsLoopback() && ip.IsPrivate() && (intf.Flags&net.FlagRunning != 0) {
				res = append(res, ip)
			}
		}
	}
	return res, nil
}

func RandChoice[T any](l []T) T {
	randIndex := rand.Intn(len(l) - 1)

	return l[randIndex]
}

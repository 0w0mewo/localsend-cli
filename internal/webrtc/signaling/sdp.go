package signaling

import (
	"bytes"
	"compress/zlib"
	"encoding/base64"
	"io"
)

// CompressSDP compresses an SDP string using zlib and encodes it as base64.
// Uses URL-safe base64 without padding to match official LocalSend protocol.
func CompressSDP(sdp string) (string, error) {
	var buf bytes.Buffer
	w := zlib.NewWriter(&buf)
	if _, err := w.Write([]byte(sdp)); err != nil {
		return "", err
	}
	if err := w.Close(); err != nil {
		return "", err
	}
	// Use URL-safe base64 without padding (matches official Rust implementation)
	return base64.RawURLEncoding.EncodeToString(buf.Bytes()), nil
}

// DecompressSDP decodes base64 and decompresses a zlib-compressed SDP string.
// Uses URL-safe base64 without padding to match official LocalSend protocol.
func DecompressSDP(compressed string) (string, error) {
	// Use URL-safe base64 without padding (matches official Rust implementation)
	data, err := base64.RawURLEncoding.DecodeString(compressed)
	if err != nil {
		return "", err
	}

	r, err := zlib.NewReader(bytes.NewReader(data))
	if err != nil {
		return "", err
	}
	defer r.Close()

	result, err := io.ReadAll(r)
	if err != nil {
		return "", err
	}

	return string(result), nil
}


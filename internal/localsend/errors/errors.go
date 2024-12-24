package errors

import (
	"errors"
)

var (
	ErrFinished        = errors.New("No file transfer needed")
	ErrInvalidBody     = errors.New("Invalid body")
	ErrRejected        = errors.New("Rejected")
	ErrInvalidPIN      = errors.New("Invalid PIN")
	ErrBlockedByOthers = errors.New("Block by another session")
	ErrUnknown         = errors.New("Unknown error")
	ErrTooManyReq      = errors.New("Too many request")
	ErrFileIO          = errors.New("File IO")
	ErrChecksum        = errors.New("sha256 mismatch")
	ErrFingerprint     = errors.New("Fingerprint mismatch")
)

func ParseError(status int) error {
	switch status {
	case 200:
		return nil
	case 204:
		return ErrFinished
	case 400:
		return ErrInvalidBody
	case 401:
		return ErrInvalidPIN
	case 403:
		return ErrRejected
	case 409:
		return ErrBlockedByOthers
	case 429:
		return ErrTooManyReq
	default:
		return ErrUnknown
	}
}

func Status(err error) int {
	switch err {
	case nil:
		return 200
	case ErrFinished:
		return 204
	case ErrInvalidBody:
		return 400
	case ErrInvalidPIN:
		return 401
	case ErrRejected:
		return 403
	case ErrBlockedByOthers:
		return 409
	case ErrTooManyReq:
		return 429
	default:
		return 500
	}
}

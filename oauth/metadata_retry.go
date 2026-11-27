package oauth

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"math/rand/v2"
	"net"
	"net/http"
	"reflect"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type metadataHTTPError struct {
	*HTTPError
	retryAfter string
}

func (e *metadataHTTPError) Unwrap() error { return e.HTTPError }

func retryableHTTPStatus(status int) bool {
	return status == http.StatusTooManyRequests || (status >= http.StatusInternalServerError && status < 600)
}

func retryableMetadataFailure(err error) bool {
	var status *HTTPError
	if errors.As(err, &status) {
		return retryableHTTPStatus(status.Status) ||
			(isSuccessStatus(status.Status) && errors.Is(err, ErrResponseBodyTooLarge))
	}
	var cert *tls.CertificateVerificationError
	var unknownAuthority x509.UnknownAuthorityError
	var hostname x509.HostnameError
	var invalidCert x509.CertificateInvalidError
	if errors.As(err, &cert) || errors.As(err, &unknownAuthority) || errors.As(err, &hostname) || errors.As(err, &invalidCert) {
		return false
	}
	var operation *net.OpError
	var timeout interface{ Timeout() bool }
	return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) ||
		errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, syscall.ECONNRESET) ||
		errors.As(err, &operation) || (errors.As(err, &timeout) && timeout.Timeout()) || http2TransportFailure(err)
}

func http2TransportFailure(err error) bool {
	for cause := err; cause != nil; cause = errors.Unwrap(cause) {
		// The standard library does not export its HTTP/2 error types: they are in
		// net/http before Go 1.27 and in net/http/internal/http2 from Go 1.27.
		kind := reflect.TypeOf(cause)
		switch kind.PkgPath() {
		case "net/http":
			switch kind.Name() {
			case "http2StreamError", "http2ConnectionError", "http2GoAwayError":
				return true
			}
		case "net/http/internal/http2", "golang.org/x/net/http2":
			switch kind.Name() {
			case "StreamError", "ConnectionError", "GoAwayError":
				return true
			}
		}
	}
	return false
}

type metadataRetry struct {
	err        error
	until      time.Time
	next       time.Duration
	recordedAt time.Time
}

func (r metadataRetry) failure(now time.Time) error {
	if now.Before(r.until) {
		return r.err
	}
	return nil
}

func (r metadataRetry) record(now time.Time, err error) metadataRetry {
	if errors.Is(err, context.Canceled) || !retryableMetadataFailure(err) {
		return r
	}
	var status *HTTPError
	if errors.As(err, &status) && isSuccessStatus(status.Status) {
		return r
	}
	if status != nil && (status.Status == 429 || status.Status == 503) {
		var response *metadataHTTPError
		if errors.As(err, &response) {
			if delay, ok := metadataRetryAfter(now, response.retryAfter); ok {
				r.err, r.until = err, now.Add(delay)
				r.recordedAt = now
				return r
			}
		}
		if status.Status == 429 {
			return r
		}
	}
	if r.next == 0 {
		r.next = time.Second
	}
	delay := min(30*time.Second, time.Duration(float64(r.next)*(0.8+rand.Float64()*0.4)))
	r.err, r.until = err, now.Add(delay)
	r.recordedAt = now
	r.next = min(64*time.Second, 2*r.next)
	return r
}

func metadataRetryAfter(now time.Time, value string) (time.Duration, bool) {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0, false
	}
	if strings.IndexFunc(value, func(r rune) bool { return r < '0' || r > '9' }) == -1 {
		significant := strings.TrimLeft(value, "0")
		if len(significant) > 2 {
			return time.Minute, true
		}
		n, _ := strconv.Atoi(significant)
		return min(time.Minute, time.Duration(n)*time.Second), true
	}
	for _, format := range []string{http.TimeFormat, "Monday, 02-Jan-06 15:04:05 GMT", time.ANSIC, "Mon Jan 02 15:04:05 2006"} {
		date, err := time.Parse(format, value)
		if err != nil {
			continue
		}
		if format == "Monday, 02-Jan-06 15:04:05 GMT" {
			latest := now.UTC().AddDate(50, 0, 0)
			date = date.AddDate((latest.Year()-date.Year()+10000)/100*100-10000, 0, 0)
			if date.After(latest) {
				date = date.AddDate(-100, 0, 0)
			}
		}
		if date.Format(format) == value {
			return min(time.Minute, max(0, date.Sub(now))), true
		}
	}
	return 0, false
}

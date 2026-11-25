package oauth

import (
	"context"
	"errors"
	"math/rand/v2"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type metadataHTTPError struct {
	*HTTPError
	retryAfter string
}

func (e *metadataHTTPError) Unwrap() error { return e.HTTPError }

func retryableMetadataFailure(err error) bool {
	var status *HTTPError
	if errors.As(err, &status) {
		return status.Status == 429 || (status.Status >= 500 && status.Status < 600)
	}
	var transport net.Error
	return errors.As(err, &transport) || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}

type metadataRetry struct {
	err   error
	until time.Time
	next  time.Duration
}

func (r metadataRetry) failure(now time.Time) error {
	if now.Before(r.until) {
		return r.err
	}
	return nil
}

func (r metadataRetry) record(now time.Time, err error) metadataRetry {
	r.err = nil
	r.until = time.Time{}
	if errors.Is(err, context.Canceled) || !retryableMetadataFailure(err) {
		return r
	}
	var status *HTTPError
	if errors.As(err, &status) && (status.Status == 429 || status.Status == 503) {
		var response *metadataHTTPError
		if errors.As(err, &response) {
			if delay, ok := metadataRetryAfter(now, response.retryAfter); ok {
				r.err, r.until = err, now.Add(delay)
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
	if date, err := http.ParseTime(value); err == nil {
		return min(time.Minute, max(0, date.Sub(now))), true
	}
	return 0, false
}

package lib

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	defaultHTTPTimeout      = 45 * time.Second
	defaultHTTPMaxRetries   = 3
	defaultHTTPBackoffBase  = 2 * time.Second
	defaultHTTPBackoffLimit = 10 * time.Second
)

type httpRequestConfig struct {
	timeout      time.Duration
	maxRetries   int
	backoffBase  time.Duration
	backoffLimit time.Duration
}

func getHTTPRequestConfig() httpRequestConfig {
	cfg := httpRequestConfig{
		timeout:      getEnvDuration("GEOIP_HTTP_TIMEOUT", defaultHTTPTimeout),
		maxRetries:   getEnvInt("GEOIP_HTTP_MAX_RETRIES", defaultHTTPMaxRetries),
		backoffBase:  getEnvDuration("GEOIP_HTTP_BACKOFF_BASE", defaultHTTPBackoffBase),
		backoffLimit: getEnvDuration("GEOIP_HTTP_BACKOFF_LIMIT", defaultHTTPBackoffLimit),
	}

	if cfg.maxRetries < 1 {
		cfg.maxRetries = 1
	}
	if cfg.backoffBase < 1*time.Second {
		cfg.backoffBase = 1 * time.Second
	}
	if cfg.backoffLimit < cfg.backoffBase {
		cfg.backoffLimit = cfg.backoffBase
	}

	return cfg
}

func getEnvDuration(key string, fallback time.Duration) time.Duration {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}

	if d, err := time.ParseDuration(value); err == nil && d > 0 {
		return d
	}

	if n, err := strconv.Atoi(value); err == nil && n > 0 {
		return time.Duration(n) * time.Second
	}

	return fallback
}

func getEnvInt(key string, fallback int) int {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}

	n, err := strconv.Atoi(value)
	if err != nil || n <= 0 {
		return fallback
	}

	return n
}

func retryDelay(cfg httpRequestConfig, attempt int) time.Duration {
	delay := cfg.backoffBase
	for i := 1; i < attempt; i++ {
		delay *= 2
		if delay >= cfg.backoffLimit {
			return cfg.backoffLimit
		}
	}
	return delay
}

func isRetryableStatusCode(code int) bool {
	switch code {
	case http.StatusRequestTimeout,
		http.StatusTooEarly,
		http.StatusTooManyRequests,
		http.StatusInternalServerError,
		http.StatusBadGateway,
		http.StatusServiceUnavailable,
		http.StatusGatewayTimeout:
		return true
	default:
		return false
	}
}

func getRemoteURLResponse(url string) (*http.Response, error) {
	cfg := getHTTPRequestConfig()
	client := &http.Client{
		Timeout: cfg.timeout,
	}

	var lastErr error

	for attempt := 1; attempt <= cfg.maxRetries; attempt++ {
		resp, err := client.Get(url)
		if err != nil {
			lastErr = err
		} else {
			if resp.StatusCode == http.StatusOK {
				return resp, nil
			}

			lastErr = fmt.Errorf("%s", resp.Status)
			resp.Body.Close()

			if !isRetryableStatusCode(resp.StatusCode) {
				break
			}
		}

		if attempt < cfg.maxRetries {
			time.Sleep(retryDelay(cfg, attempt))
		}
	}

	if lastErr != nil {
		return nil, fmt.Errorf("failed to get remote content -> %s: %w", url, lastErr)
	}

	return nil, fmt.Errorf("failed to get remote content -> %s", url)
}

func GetRemoteURLContent(url string) ([]byte, error) {
	resp, err := getRemoteURLResponse(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	return io.ReadAll(resp.Body)
}

func GetRemoteURLReader(url string) (io.ReadCloser, error) {
	resp, err := getRemoteURLResponse(url)
	if err != nil {
		return nil, err
	}

	return resp.Body, nil
}

type WantedListExtended struct {
	TypeSlice []string
	TypeMap   map[string][]string
}

func (w *WantedListExtended) UnmarshalJSON(data []byte) error {
	if len(data) == 0 {
		return nil
	}

	slice := make([]string, 0)
	mapMap := make(map[string][]string, 0)

	err := json.Unmarshal(data, &slice)
	if err != nil {
		err2 := json.Unmarshal(data, &mapMap)
		if err2 != nil {
			return err2
		}
	}

	w.TypeSlice = slice
	w.TypeMap = mapMap

	return nil
}

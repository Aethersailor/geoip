package main

import (
	"bufio"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/oschwald/geoip2-golang"
	"github.com/oschwald/maxminddb-golang"
	"go4.org/netipx"
)

const maxDownloadSize = 64 << 20

var specialUsePrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.88.99.0/24"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("224.0.0.0/4"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("::/128"),
	netip.MustParsePrefix("::1/128"),
	netip.MustParsePrefix("64:ff9b:1::/48"),
	netip.MustParsePrefix("100::/64"),
	netip.MustParsePrefix("2001:2::/48"),
	netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("fc00::/7"),
	netip.MustParsePrefix("fe80::/10"),
	netip.MustParsePrefix("ff00::/8"),
}

type manifest struct {
	Sources []source `json:"sources"`
}

type source struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	Format   string   `json:"format"`
	URLs     []string `json:"urls"`
	License  string   `json:"license"`
	Required bool     `json:"required"`
	TokenEnv string   `json:"tokenEnv,omitempty"`
}

type sourceResult struct {
	ID              string `json:"id"`
	Name            string `json:"name"`
	Status          string `json:"status"`
	Required        bool   `json:"required"`
	License         string `json:"license"`
	ResolvedURL     string `json:"resolvedUrl,omitempty"`
	SHA256          string `json:"sha256,omitempty"`
	DownloadedBytes int64  `json:"downloadedBytes,omitempty"`
	RawRecords      int    `json:"rawRecords"`
	AcceptedRecords int    `json:"acceptedRecords"`
	RejectedRecords int    `json:"rejectedRecords"`
	CanonicalCIDRs  int    `json:"canonicalCidrs"`
	UniqueCIDRs     int    `json:"uniqueCidrs"`
	UniqueAddresses string `json:"uniqueAddresses"`
	Error           string `json:"error,omitempty"`
	set             *netipx.IPSet
}

type report struct {
	GeneratedAt       string         `json:"generatedAt"`
	CombinedCIDRs     int            `json:"combinedCidrs"`
	CombinedIPv4      int            `json:"combinedIpv4Cidrs"`
	CombinedIPv6      int            `json:"combinedIpv6Cidrs"`
	CombinedAddresses string         `json:"combinedAddresses"`
	Sources           []sourceResult `json:"sources"`
}

type ipInfoLite struct {
	CountryCode string `maxminddb:"country_code"`
}

func main() {
	manifestPath := flag.String("manifest", "sources/cn.json", "source manifest")
	outputPath := flag.String("output", ".cache/geoip-sources/cn.txt", "normalized CN output")
	reportPath := flag.String("report", ".cache/source-report.json", "audit report")
	flag.Parse()

	if err := run(*manifestPath, *outputPath, *reportPath); err != nil {
		fmt.Fprintln(os.Stderr, "source preparation failed:", err)
		os.Exit(1)
	}
}

func run(manifestPath, outputPath, reportPath string) error {
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		return err
	}
	var cfg manifest
	if err := json.Unmarshal(data, &cfg); err != nil {
		return err
	}
	if len(cfg.Sources) == 0 {
		return errors.New("source manifest is empty")
	}

	client := &http.Client{Timeout: 90 * time.Second}
	results := make([]sourceResult, 0, len(cfg.Sources))
	for _, src := range cfg.Sources {
		result := prepareSource(client, src)
		results = append(results, result)
		fmt.Printf("%-20s %-8s cidrs=%d accepted=%d rejected=%d\n", src.ID, result.Status, result.CanonicalCIDRs, result.AcceptedRecords, result.RejectedRecords)
		if result.Status == "failed" && src.Required {
			return fmt.Errorf("required source %s: %s", src.ID, result.Error)
		}
	}

	combinedBuilder := new(netipx.IPSetBuilder)
	for i := range results {
		if results[i].set != nil {
			combinedBuilder.AddSet(results[i].set)
		}
	}
	combined, err := combinedBuilder.IPSet()
	if err != nil {
		return err
	}
	if len(combined.Prefixes()) == 0 {
		return errors.New("combined CN source set is empty")
	}

	for i := range results {
		if results[i].set == nil {
			continue
		}
		othersBuilder := new(netipx.IPSetBuilder)
		for j := range results {
			if i != j && results[j].set != nil {
				othersBuilder.AddSet(results[j].set)
			}
		}
		others, err := othersBuilder.IPSet()
		if err != nil {
			return err
		}
		uniqueBuilder := new(netipx.IPSetBuilder)
		uniqueBuilder.AddSet(results[i].set)
		uniqueBuilder.RemoveSet(others)
		unique, err := uniqueBuilder.IPSet()
		if err != nil {
			return err
		}
		results[i].UniqueCIDRs = len(unique.Prefixes())
		results[i].UniqueAddresses = addressCount(unique.Prefixes()).String()
	}

	if err := writePrefixes(outputPath, combined.Prefixes()); err != nil {
		return err
	}
	v4, v6 := 0, 0
	for _, prefix := range combined.Prefixes() {
		if prefix.Addr().Is4() {
			v4++
		} else {
			v6++
		}
	}
	audit := report{
		GeneratedAt:       time.Now().UTC().Format(time.RFC3339),
		CombinedCIDRs:     len(combined.Prefixes()),
		CombinedIPv4:      v4,
		CombinedIPv6:      v6,
		CombinedAddresses: addressCount(combined.Prefixes()).String(),
		Sources:           results,
	}
	for i := range audit.Sources {
		audit.Sources[i].set = nil
	}
	return writeJSON(reportPath, audit)
}

func prepareSource(client *http.Client, src source) sourceResult {
	result := sourceResult{ID: src.ID, Name: src.Name, Required: src.Required, License: src.License, Status: "failed", UniqueAddresses: "0"}
	urls, disabled := resolveURLs(src)
	if disabled {
		result.Status = "disabled"
		return result
	}
	var data []byte
	var err error
	for _, candidate := range urls {
		data, err = download(client, candidate)
		if err == nil {
			result.ResolvedURL = redactURL(candidate)
			break
		}
	}
	if err != nil {
		result.Error = err.Error()
		if !src.Required {
			result.Status = "skipped"
		}
		return result
	}
	result.DownloadedBytes = int64(len(data))
	sum := sha256.Sum256(data)
	result.SHA256 = hex.EncodeToString(sum[:])

	var parsed parseResult
	switch src.Format {
	case "text":
		parsed, err = parseText(strings.NewReader(string(data)))
	case "country-cidr-csv":
		parsed, err = parseCountryCIDRCSV(strings.NewReader(string(data)))
	case "dbip-mmdb-gzip":
		reader, gzipErr := gzip.NewReader(strings.NewReader(string(data)))
		if gzipErr != nil {
			err = gzipErr
			break
		}
		mmdb, readErr := io.ReadAll(io.LimitReader(reader, maxDownloadSize+1))
		closeErr := reader.Close()
		if readErr != nil {
			err = readErr
		} else if closeErr != nil {
			err = closeErr
		} else if len(mmdb) > maxDownloadSize {
			err = errors.New("decompressed MMDB exceeds size limit")
		} else {
			parsed, err = parseMMDB(mmdb, false)
		}
	case "ipinfo-mmdb":
		parsed, err = parseMMDB(data, true)
	default:
		err = fmt.Errorf("unsupported format %q", src.Format)
	}
	if err != nil {
		result.Error = err.Error()
		if !src.Required {
			result.Status = "skipped"
		}
		return result
	}
	result.Status = "enabled"
	result.RawRecords = parsed.raw
	result.AcceptedRecords = parsed.accepted
	result.RejectedRecords = parsed.rejected
	result.CanonicalCIDRs = len(parsed.set.Prefixes())
	result.set = parsed.set
	return result
}

type parseResult struct {
	raw      int
	accepted int
	rejected int
	set      *netipx.IPSet
}

func parseText(reader io.Reader) (parseResult, error) {
	builder := new(netipx.IPSetBuilder)
	result := parseResult{}
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
			continue
		}
		result.raw++
		line, _, _ = strings.Cut(line, "#")
		line = strings.TrimSpace(line)
		prefix, err := parsePrefix(line)
		if err != nil || !isPublicPrefix(prefix) {
			result.rejected++
			continue
		}
		builder.AddPrefix(prefix)
		result.accepted++
	}
	if err := scanner.Err(); err != nil {
		return result, err
	}
	set, err := builder.IPSet()
	result.set = set
	return result, err
}

func parseCountryCIDRCSV(reader io.Reader) (parseResult, error) {
	builder := new(netipx.IPSetBuilder)
	result := parseResult{}
	csvReader := csv.NewReader(reader)
	csvReader.FieldsPerRecord = -1
	for {
		record, err := csvReader.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return result, err
		}
		result.raw++
		if len(record) < 2 || !strings.EqualFold(strings.TrimSpace(record[1]), "CN") {
			continue
		}
		prefix, err := parsePrefix(strings.TrimSpace(record[0]))
		if err != nil || !isPublicPrefix(prefix) {
			result.rejected++
			continue
		}
		builder.AddPrefix(prefix)
		result.accepted++
	}
	set, err := builder.IPSet()
	result.set = set
	return result, err
}

func parseMMDB(data []byte, ipinfo bool) (parseResult, error) {
	db, err := maxminddb.FromBytes(data)
	if err != nil {
		return parseResult{}, err
	}
	defer db.Close()
	builder := new(netipx.IPSetBuilder)
	result := parseResult{}
	networks := db.Networks(maxminddb.SkipAliasedNetworks)
	for networks.Next() {
		result.raw++
		var subnet *net.IPNet
		var country string
		if ipinfo {
			var record ipInfoLite
			subnet, err = networks.Network(&record)
			country = record.CountryCode
		} else {
			var record geoip2.Country
			subnet, err = networks.Network(&record)
			country = record.Country.IsoCode
			if country == "" {
				country = record.RegisteredCountry.IsoCode
			}
			if country == "" {
				country = record.RepresentedCountry.IsoCode
			}
		}
		if err != nil {
			return result, err
		}
		if !strings.EqualFold(strings.TrimSpace(country), "CN") {
			continue
		}
		prefix, ok := netipx.FromStdIPNet(subnet)
		if !ok || !isPublicPrefix(prefix) {
			result.rejected++
			continue
		}
		builder.AddPrefix(prefix)
		result.accepted++
	}
	if err := networks.Err(); err != nil {
		return result, err
	}
	set, err := builder.IPSet()
	result.set = set
	return result, err
}

func parsePrefix(value string) (netip.Prefix, error) {
	if strings.Contains(value, "/") {
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			return netip.Prefix{}, err
		}
		return prefix.Masked(), nil
	}
	addr, err := netip.ParseAddr(value)
	if err != nil {
		return netip.Prefix{}, err
	}
	addr = addr.Unmap()
	return netip.PrefixFrom(addr, addr.BitLen()), nil
}

func isPublicPrefix(prefix netip.Prefix) bool {
	addr := prefix.Addr().Unmap()
	if !addr.IsValid() || addr.IsUnspecified() || addr.IsLoopback() || addr.IsPrivate() || addr.IsMulticast() || addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast() {
		return false
	}
	for _, reserved := range specialUsePrefixes {
		if prefix.Overlaps(reserved) {
			return false
		}
	}
	return true
}

func resolveURLs(src source) ([]string, bool) {
	token := ""
	if src.TokenEnv != "" {
		token = strings.TrimSpace(os.Getenv(src.TokenEnv))
		if token == "" {
			return nil, true
		}
	}
	now := time.Now().UTC()
	previous := now.AddDate(0, -1, 0)
	resolved := make([]string, 0, len(src.URLs))
	for _, candidate := range src.URLs {
		candidate = strings.ReplaceAll(candidate, "{current-month}", now.Format("2006-01"))
		candidate = strings.ReplaceAll(candidate, "{previous-month}", previous.Format("2006-01"))
		candidate = strings.ReplaceAll(candidate, "{token}", url.QueryEscape(token))
		resolved = append(resolved, candidate)
	}
	return resolved, false
}

func download(client *http.Client, sourceURL string) ([]byte, error) {
	var lastErr error
	for attempt := 1; attempt <= 3; attempt++ {
		ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, sourceURL, nil)
		if err != nil {
			cancel()
			return nil, err
		}
		req.Header.Set("User-Agent", "Aethersailor-geoip-sourceprep/1")
		response, err := client.Do(req)
		if err == nil && response.StatusCode >= 200 && response.StatusCode < 300 {
			body, readErr := io.ReadAll(io.LimitReader(response.Body, maxDownloadSize+1))
			closeErr := response.Body.Close()
			cancel()
			if readErr != nil {
				lastErr = readErr
			} else if closeErr != nil {
				lastErr = closeErr
			} else if len(body) > maxDownloadSize {
				lastErr = errors.New("download exceeds size limit")
			} else {
				return body, nil
			}
		} else {
			if response != nil {
				lastErr = fmt.Errorf("HTTP %s", response.Status)
				response.Body.Close()
			} else {
				lastErr = err
			}
			cancel()
		}
		if attempt < 3 {
			time.Sleep(time.Duration(attempt) * time.Second)
		}
	}
	return nil, lastErr
}

func redactURL(value string) string {
	parsed, err := url.Parse(value)
	if err != nil {
		return value
	}
	if parsed.Query().Has("token") {
		query := parsed.Query()
		query.Set("token", "REDACTED")
		parsed.RawQuery = query.Encode()
	}
	return parsed.String()
}

func addressCount(prefixes []netip.Prefix) *big.Int {
	total := new(big.Int)
	for _, prefix := range prefixes {
		bits := prefix.Addr().BitLen() - prefix.Bits()
		total.Add(total, new(big.Int).Lsh(big.NewInt(1), uint(bits)))
	}
	return total
}

func writePrefixes(path string, prefixes []netip.Prefix) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	var builder strings.Builder
	for _, prefix := range prefixes {
		builder.WriteString(prefix.String())
		builder.WriteByte('\n')
	}
	return os.WriteFile(path, []byte(builder.String()), 0o644)
}

func writeJSON(path string, value any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return os.WriteFile(path, data, 0o644)
}

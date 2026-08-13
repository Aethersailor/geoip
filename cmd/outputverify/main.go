package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/Loyalsoldier/geoip/lib"
	"github.com/Loyalsoldier/geoip/plugin/maxmind"
	"github.com/Loyalsoldier/geoip/plugin/mihomo"
	"github.com/Loyalsoldier/geoip/plugin/plaintext"
	"github.com/Loyalsoldier/geoip/plugin/singbox"
	"github.com/Loyalsoldier/geoip/plugin/v2ray"
)

type buildInfo struct {
	GeneratedAt string `json:"generatedAt"`
	CommitSHA   string `json:"commitSha,omitempty"`
	RunID       string `json:"runId,omitempty"`
	CNPrefixes  int    `json:"cnPrefixes"`
	CNIPv4      int    `json:"cnIpv4Prefixes"`
	CNIPv6      int    `json:"cnIpv6Prefixes"`
}

func main() {
	outputDir := flag.String("output", "output", "generated output directory")
	sourceReport := flag.String("source-report", ".cache/source-report.json", "source audit report")
	flag.Parse()

	if err := run(*outputDir, *sourceReport); err != nil {
		fmt.Fprintln(os.Stderr, "output verification failed:", err)
		os.Exit(1)
	}
}

func run(outputDir, sourceReport string) error {
	referencePath := filepath.Join(outputDir, "text", "cn.txt")
	reference, err := loadEntry(&plaintext.TextIn{
		Type: plaintext.TypeTextIn, Action: lib.ActionAdd, Name: "cn", URI: referencePath,
	})
	if err != nil {
		return fmt.Errorf("reference CN text: %w", err)
	}
	canonical, err := reference.MarshalText()
	if err != nil {
		return err
	}
	rawLines, err := readLines(referencePath)
	if err != nil {
		return err
	}
	if !slices.Equal(rawLines, canonical) {
		return errors.New("text/cn.txt is duplicated, non-canonical, reducible, or unsorted")
	}

	v4, v6 := splitByFamily(canonical)
	if err := compareTextFile(filepath.Join(outputDir, "text", "cn-ipv4.txt"), v4); err != nil {
		return err
	}
	if err := compareTextFile(filepath.Join(outputDir, "text", "cn-ipv6.txt"), v6); err != nil {
		return err
	}

	checks := []struct {
		name      string
		converter lib.InputConverter
	}{
		{"Clash classical", &plaintext.TextIn{Type: plaintext.TypeClashRuleSetClassicalIn, Action: lib.ActionAdd, Name: "cn", URI: filepath.Join(outputDir, "clash", "classical", "cn.txt")}},
		{"Clash IP-CIDR", &plaintext.TextIn{Type: plaintext.TypeClashRuleSetIPCIDRIn, Action: lib.ActionAdd, Name: "cn", URI: filepath.Join(outputDir, "clash", "ipcidr", "cn.txt")}},
		{"Surge", &plaintext.TextIn{Type: plaintext.TypeSurgeRuleSetIn, Action: lib.ActionAdd, Name: "cn", URI: filepath.Join(outputDir, "surge", "cn.txt")}},
		{"V2Ray DAT", &v2ray.GeoIPDatIn{Type: v2ray.TypeGeoIPDatIn, Action: lib.ActionAdd, URI: filepath.Join(outputDir, "geoip-only-cn-private.dat"), Want: map[string]bool{"CN": true}}},
		{"sing-box SRS", &singbox.SRSIn{Type: singbox.TypeSRSIn, Action: lib.ActionAdd, Name: "cn", URI: filepath.Join(outputDir, "srs", "cn.srs")}},
		{"mihomo MRS", &mihomo.MRSIn{Type: mihomo.TypeMRSIn, Action: lib.ActionAdd, Name: "cn", URI: filepath.Join(outputDir, "mrs", "cn.mrs")}},
		{"MaxMind MMDB", &maxmind.GeoLite2CountryMMDBIn{Type: maxmind.TypeGeoLite2CountryMMDBIn, Action: lib.ActionAdd, URI: filepath.Join(outputDir, "Country-only-cn-private.mmdb"), Want: map[string]bool{"CN": true}}},
	}
	for _, check := range checks {
		entry, err := loadEntry(check.converter)
		if err != nil {
			return fmt.Errorf("%s: %w", check.name, err)
		}
		got, err := entry.MarshalText()
		if err != nil {
			return fmt.Errorf("%s: %w", check.name, err)
		}
		if !slices.Equal(got, canonical) {
			return fmt.Errorf("%s CN set differs from text/cn.txt", check.name)
		}
		fmt.Printf("verified %-18s %d prefixes\n", check.name, len(got))
	}

	if err := copyFile(sourceReport, filepath.Join(outputDir, "source-report.json")); err != nil {
		return err
	}
	if err := generateChecksums(outputDir); err != nil {
		return err
	}
	info := buildInfo{
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		CommitSHA:   os.Getenv("GITHUB_SHA"),
		RunID:       os.Getenv("GITHUB_RUN_ID"),
		CNPrefixes:  len(canonical),
		CNIPv4:      len(v4),
		CNIPv6:      len(v6),
	}
	if err := writeJSON(filepath.Join(outputDir, "build-info.json"), info); err != nil {
		return err
	}
	if err := generateManifest(outputDir); err != nil {
		return err
	}
	fmt.Printf("verified canonical CN union: %d IPv4 + %d IPv6 = %d prefixes\n", len(v4), len(v6), len(canonical))
	return nil
}

func loadEntry(converter lib.InputConverter) (*lib.Entry, error) {
	container, err := converter.Input(lib.NewContainer())
	if err != nil {
		return nil, err
	}
	entry, ok := container.GetEntry("cn")
	if !ok {
		return nil, errors.New("CN entry not found")
	}
	return entry, nil
}

func compareTextFile(path string, want []string) error {
	got, err := readLines(path)
	if err != nil {
		return err
	}
	if !slices.Equal(got, want) {
		return fmt.Errorf("%s differs from canonical CN set", filepath.ToSlash(path))
	}
	return nil
}

func readLines(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			lines = append(lines, line)
		}
	}
	return lines, scanner.Err()
}

func splitByFamily(prefixes []string) ([]string, []string) {
	v4 := make([]string, 0, len(prefixes))
	v6 := make([]string, 0, len(prefixes))
	for _, value := range prefixes {
		prefix := netip.MustParsePrefix(value)
		if prefix.Addr().Is4() {
			v4 = append(v4, value)
		} else {
			v6 = append(v6, value)
		}
	}
	return v4, v6
}

func generateChecksums(outputDir string) error {
	entries, err := os.ReadDir(outputDir)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.IsDir() || (!strings.HasSuffix(entry.Name(), ".dat") && !strings.HasSuffix(entry.Name(), ".mmdb")) {
			continue
		}
		path := filepath.Join(outputDir, entry.Name())
		sum, err := fileSHA256(path)
		if err != nil {
			return err
		}
		content := fmt.Sprintf("%s  %s\n", sum, entry.Name())
		if err := os.WriteFile(path+".sha256sum", []byte(content), 0o644); err != nil {
			return err
		}
	}
	return nil
}

func generateManifest(outputDir string) error {
	var lines []string
	err := filepath.Walk(outputDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		relative, err := filepath.Rel(outputDir, path)
		if err != nil {
			return err
		}
		relative = filepath.ToSlash(relative)
		switch relative {
		case "build-info.json", "source-report.json", "content-manifest.sha256":
			return nil
		}
		sum, err := fileSHA256(path)
		if err != nil {
			return err
		}
		lines = append(lines, fmt.Sprintf("%s  %s", sum, relative))
		return nil
	})
	if err != nil {
		return err
	}
	slices.Sort(lines)
	return os.WriteFile(filepath.Join(outputDir, "content-manifest.sha256"), []byte(strings.Join(lines, "\n")+"\n"), 0o644)
}

func fileSHA256(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func copyFile(source, destination string) error {
	data, err := os.ReadFile(source)
	if err != nil {
		return err
	}
	return os.WriteFile(destination, data, 0o644)
}

func writeJSON(path string, value any) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0o644)
}

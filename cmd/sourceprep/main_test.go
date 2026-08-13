package main

import (
	"strings"
	"testing"
)

func TestParseTextCanonicalizesAndRejectsPrivateRanges(t *testing.T) {
	t.Parallel()

	parsed, err := parseText(strings.NewReader("# header\n1.0.1.1/24\n1.0.1.0/25\n10.0.0.0/8\ninvalid\n"))
	if err != nil {
		t.Fatal(err)
	}
	got := parsed.set.Prefixes()
	if len(got) != 1 || got[0].String() != "1.0.1.0/24" {
		t.Fatalf("prefixes = %v", got)
	}
	if parsed.accepted != 2 || parsed.rejected != 2 {
		t.Fatalf("accepted=%d rejected=%d", parsed.accepted, parsed.rejected)
	}
}

func TestParseCountryCIDRCSVFiltersCN(t *testing.T) {
	t.Parallel()

	parsed, err := parseCountryCIDRCSV(strings.NewReader("1.0.1.0/24,CN\n8.8.8.0/24,US\n2400:3200::/32,CN\n"))
	if err != nil {
		t.Fatal(err)
	}
	got := parsed.set.Prefixes()
	if len(got) != 2 || got[0].String() != "1.0.1.0/24" || got[1].String() != "2400:3200::/32" {
		t.Fatalf("prefixes = %v", got)
	}
}

func TestRedactURL(t *testing.T) {
	t.Parallel()

	got := redactURL("https://example.test/file?token=secret&x=1")
	if strings.Contains(got, "secret") || !strings.Contains(got, "REDACTED") {
		t.Fatalf("redacted URL = %q", got)
	}
}

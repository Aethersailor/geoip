package lib

import (
	"reflect"
	"testing"
)

func TestEntryCanonicalizesAndDeduplicatesPrefixes(t *testing.T) {
	t.Parallel()

	entry := NewEntry("cn")
	for _, prefix := range []string{
		"10.0.0.1/24",
		"10.0.0.0/25",
		"10.0.0.128/25",
		"10.0.1.0/24",
		"2001:db8::/33",
		"2001:db8:8000::/33",
	} {
		if err := entry.AddPrefix(prefix); err != nil {
			t.Fatalf("AddPrefix(%q): %v", prefix, err)
		}
	}

	got, err := entry.MarshalText()
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"10.0.0.0/23", "2001:db8::/32"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("canonical prefixes = %v, want %v", got, want)
	}
}

func TestEntryInvalidatesCachedSetsAfterMutation(t *testing.T) {
	t.Parallel()

	entry := NewEntry("cn")
	if err := entry.AddPrefix("192.0.2.0/25"); err != nil {
		t.Fatal(err)
	}
	if _, err := entry.MarshalText(); err != nil {
		t.Fatal(err)
	}
	if err := entry.AddPrefix("192.0.2.128/25"); err != nil {
		t.Fatal(err)
	}
	if err := entry.RemovePrefix("192.0.2.128/26"); err != nil {
		t.Fatal(err)
	}

	got, err := entry.MarshalText()
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"192.0.2.0/25", "192.0.2.192/26"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("mutated prefixes = %v, want %v", got, want)
	}
}

func TestEntryIgnoresCommentOnlyLines(t *testing.T) {
	t.Parallel()

	entry := NewEntry("cn")
	for _, line := range []string{"", "  # comment", "// comment", "/* comment"} {
		if err := entry.AddPrefix(line); err != nil {
			t.Fatalf("AddPrefix(%q): %v", line, err)
		}
		if err := entry.RemovePrefix(line); err != nil {
			t.Fatalf("RemovePrefix(%q): %v", line, err)
		}
	}
}

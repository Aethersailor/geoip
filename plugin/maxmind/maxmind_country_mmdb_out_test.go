package maxmind

import "testing"

func TestSourceDateEpoch(t *testing.T) {
	t.Setenv("SOURCE_DATE_EPOCH", "1700000000")
	got, err := sourceDateEpoch()
	if err != nil {
		t.Fatal(err)
	}
	if got != 1700000000 {
		t.Fatalf("epoch = %d", got)
	}
}

func TestSourceDateEpochRejectsInvalidValue(t *testing.T) {
	t.Setenv("SOURCE_DATE_EPOCH", "not-a-number")
	if _, err := sourceDateEpoch(); err == nil {
		t.Fatal("invalid epoch was accepted")
	}
}

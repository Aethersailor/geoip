package lib

import (
	"reflect"
	"testing"
)

func TestContainerInvalidatesCachedSetsAfterAddAndRemove(t *testing.T) {
	t.Parallel()

	container := NewContainer()
	left := NewEntry("cn")
	if err := left.AddPrefix("198.51.100.0/25"); err != nil {
		t.Fatal(err)
	}
	if err := container.Add(left); err != nil {
		t.Fatal(err)
	}
	stored, _ := container.GetEntry("cn")
	if _, err := stored.MarshalText(); err != nil {
		t.Fatal(err)
	}

	right := NewEntry("cn")
	if err := right.AddPrefix("198.51.100.128/25"); err != nil {
		t.Fatal(err)
	}
	if err := container.Add(right); err != nil {
		t.Fatal(err)
	}
	got, err := stored.MarshalText()
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"198.51.100.0/24"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("after add = %v, want %v", got, want)
	}

	remove := NewEntry("cn")
	if err := remove.AddPrefix("198.51.100.128/26"); err != nil {
		t.Fatal(err)
	}
	if err := container.Remove(remove, CaseRemovePrefix); err != nil {
		t.Fatal(err)
	}
	got, err = stored.MarshalText()
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"198.51.100.0/25", "198.51.100.192/26"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("after remove = %v, want %v", got, want)
	}
}

func TestContainerRejectsNilEntry(t *testing.T) {
	t.Parallel()

	container := NewContainer()
	if err := container.Add(nil); err == nil {
		t.Fatal("Add(nil) succeeded")
	}
	if err := container.Remove(nil, CaseRemoveEntry); err == nil {
		t.Fatal("Remove(nil) succeeded")
	}
}

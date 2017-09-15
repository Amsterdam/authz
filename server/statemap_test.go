package server

import (
	"testing"
	"time"
)

func TestStateMap(t *testing.T) {
	key, value := "key", "value"
	m := newStateMap()
	// test persistence
	m.Persist(key, value, time.Duration(2)*time.Second)
	// restore
	if res, err := m.Restore(key); err != nil {
		t.Fatal(err)
	} else if res != value {
		t.Fatalf("Unexpected result: %s != %s", res, value)
	}
	// same key should be missing now
	if _, err := m.Restore(key); err == nil {
		t.Fatal("Key wasn't deleted from map!")
	}
	// persist and let timeout pass
	m.Persist(key, value, time.Duration(1)*time.Nanosecond)
	time.Sleep(2 * time.Nanosecond)
	if _, err := m.Restore(key); err == nil {
		t.Fatal("timout didn't work")
	}
}

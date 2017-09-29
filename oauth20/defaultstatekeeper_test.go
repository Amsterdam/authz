package oauth20

import (
	"testing"
	"time"
)

func TestStateMap(t *testing.T) {
	key, value := "key", "value"
	m := newStateMap()
	// test persistence
	if err := m.Persist(key, value, 2*time.Second); err != nil {
		t.Fatal(err)
	}
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
	m.Persist(key, value, time.Nanosecond)
	time.Sleep(2 * time.Nanosecond)
	if _, err := m.Restore(key); err == nil {
		t.Fatal("timout didn't work")
	}
}

package cli

import (
	"testing"

	"github.com/cloptima/cloptima-treehouse/internal/loginitem"
)

func TestLoginItemActive(t *testing.T) {
	cases := map[loginitem.Status]bool{
		loginitem.StatusEnabled:          true,
		loginitem.StatusRequiresApproval: true,
		loginitem.StatusNotRegistered:    false,
		loginitem.StatusNotFound:         false,
		loginitem.StatusUnknown:          false,
	}
	for status, want := range cases {
		if got := loginItemActive(status); got != want {
			t.Errorf("loginItemActive(%d) = %v, want %v", status, got, want)
		}
	}
}

func TestLaunchAtLoginResolution(t *testing.T) {
	on, off := true, false
	cases := []struct {
		name           string
		saved          bool
		userSet        bool
		active         bool
		registerFailed bool
		wantPersist    *bool
		wantShow       bool
	}{
		{"first run, registered ok", false, false, true, false, &on, true},
		{"first run, already active", false, false, true, false, &on, true},
		{"first run, registration failed", false, false, false, true, nil, false},
		{"chosen on, OS still on", true, true, true, false, nil, true},
		{"chosen off, OS still off", false, true, false, false, nil, false},
		{"chosen on, user disabled in Settings", true, true, false, false, &off, false},
		{"chosen off, user enabled in Settings", false, true, true, false, &on, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			persist, show := launchAtLoginResolution(c.saved, c.userSet, c.active, c.registerFailed)
			if show != c.wantShow {
				t.Errorf("show = %v, want %v", show, c.wantShow)
			}
			switch {
			case c.wantPersist == nil && persist != nil:
				t.Errorf("persist = %v, want nil", *persist)
			case c.wantPersist != nil && persist == nil:
				t.Errorf("persist = nil, want %v", *c.wantPersist)
			case c.wantPersist != nil && *persist != *c.wantPersist:
				t.Errorf("persist = %v, want %v", *persist, *c.wantPersist)
			}
		})
	}
}

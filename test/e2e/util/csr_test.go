package util

import (
	"math"
	"testing"
	"time"
)

func TestRenewTimeFromNotAfter(t *testing.T) {
	tests := map[string]struct {
		notBefore, notAfter time.Time
		renewBeforeString   string
		expDuration         time.Duration
		expError            bool
	}{
		"should error if renew before cannot be parsed": {
			notAfter:          time.Time{},
			notBefore:         time.Time{},
			renewBeforeString: "foo",
			expDuration:       0,
			expError:          true,
		},

		"should return duration of  20 seconds if not after is in 30s": {
			notAfter:          time.Now().Add(time.Second * 30),
			notBefore:         time.Now(),
			renewBeforeString: "10s",
			expDuration:       time.Second * 20,
			expError:          false,
		},

		"should not return duration error if renew time is in the past": {
			notAfter:          time.Now().Add(time.Second * 20),
			notBefore:         time.Now().Add(-time.Second * 10),
			renewBeforeString: "25s",
			expDuration:       -5 * time.Second,
			expError:          false,
		},

		"should return duration error if renew time is longer than certificate validity": {
			notAfter:          time.Now().Add(time.Second * 30),
			notBefore:         time.Now(),
			renewBeforeString: "35s",
			expDuration:       0,
			expError:          true,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			dur, err := RenewTimeFromNotAfter(test.notBefore, test.notAfter, test.renewBeforeString)
			if err != nil && !test.expError {
				t.Errorf("expected no error but got=%s", err)
			}

			if err == nil && test.expError {
				t.Error("expected error but got nil")
			}

			if math.Round(dur.Seconds()) != test.expDuration.Seconds() {
				t.Errorf("got unexpected duration, exp=%s got=%s", test.expDuration, dur)
			}
		})
	}
}

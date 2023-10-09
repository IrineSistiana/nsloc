package track

import (
	"testing"

	"github.com/stretchr/testify/require"
	ps "github.com/weppos/publicsuffix-go/publicsuffix"
)

func Test_cutLv(t *testing.T) {
	type args struct {
		fqdn string
		lv   int
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{"0", args{"a.b.c.", 0}, "a.b.c."},
		{"1", args{"a.b.c.", 1}, "c."},
		{"2", args{"a.b.c.", 2}, "b.c."},
		{"99", args{"a.b.c.", 99}, "a.b.c."},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := cutLv(tt.args.fqdn, tt.args.lv); got != tt.want {
				t.Errorf("cutLv() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_Psl(t *testing.T) {
	r := require.New(t)
	psl := ps.DefaultList
	d, err := ps.DomainFromListWithOptions(psl, "wew.ck", nil)
	r.NoError(err)
	logger.Info(d)
}

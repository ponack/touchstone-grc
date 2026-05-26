package config

import (
	"net/url"
	"testing"
)

// TestDSN_EscapesSpecialChars guards against the v0.1.0 regression
// where a password containing url-reserved characters (e.g. < , !) was
// interpolated unescaped and crashed golang-migrate at startup with
// "net/url: invalid userinfo".
func TestDSN_EscapesSpecialChars(t *testing.T) {
	cases := []struct {
		name     string
		password string
	}{
		{"angle bracket", "aMY<WRg1YN"},
		{"comma + bang", "aMY!1YN,y"},
		{"at sign", "p@ssw0rd"},
		{"colon", "p:ssw0rd"},
		{"slash", "p/w"},
		{"question + hash", "p?w#x"},
		{"simple alnum", "simplePassword123"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := PostgresConfig{
				Host: "postgres", Port: "5432", DB: "touchstone",
				User: "touchstone", Password: tc.password,
			}
			dsn := p.DSN()
			u, err := url.Parse(dsn)
			if err != nil {
				t.Fatalf("DSN must round-trip through url.Parse: %v\nDSN=%s", err, dsn)
			}
			gotPass, _ := u.User.Password()
			if gotPass != tc.password {
				t.Fatalf("password not preserved: got %q want %q", gotPass, tc.password)
			}
			if u.User.Username() != "touchstone" {
				t.Fatalf("user: got %q", u.User.Username())
			}
			if u.Host != "postgres:5432" {
				t.Fatalf("host: got %q", u.Host)
			}
			if u.Path != "/touchstone" {
				t.Fatalf("path: got %q", u.Path)
			}
			if u.Query().Get("sslmode") != "disable" {
				t.Fatalf("sslmode: got %q", u.Query().Get("sslmode"))
			}
		})
	}
}

package redact

import (
	"strings"
	"testing"

	"github.com/domnit/curd/internal/api"
	"github.com/domnit/curd/internal/creds"
)

func TestRedactor(t *testing.T) {
	r := New(FromCredentials(&creds.Credentials{
		Cookies:      []creds.Cookie{{Name: "session", Value: "sess-SECRET-1"}, {Name: "flag", Value: "1"}},
		LocalStorage: []creds.LocalStorageItem{{Origin: "https://app.example.com", Key: "authToken", Value: "tok/SECRET+2"}},
	})...)
	got := r.String(`{"s":"sess-SECRET-1","t":"tok/SECRET+2","u":"?t=tok%2FSECRET%2B2","n":1}`)
	if strings.Contains(got, "SECRET") {
		t.Fatalf("leak: %s", got)
	}
	if !strings.Contains(got, "{cookie:session}") || !strings.Contains(got, "{ls:https://app.example.com:authToken}") {
		t.Fatalf("placeholders missing: %s", got)
	}
	if !strings.Contains(got, `"n":1`) {
		t.Fatalf("short value redacted: %s", got)
	}
	r.Add(Secret{"late-SECRET-3", "{cookie:late}"})
	if r.String("x late-SECRET-3") != "x {cookie:late}" {
		t.Fatal("added secret not redacted")
	}
}

func TestHeaders(t *testing.T) {
	r := New()
	h := r.Headers([]api.Header{
		{Name: "Cookie", Value: "a=unknownSECRET; b=other"},
		{Name: "Set-Cookie", Value: "a=newSECRET; Path=/; HttpOnly"},
		{Name: "Authorization", Value: "Bearer abcSECRET"},
		{Name: "Accept", Value: "*/*"},
	})
	for _, x := range h {
		if strings.Contains(x.Value, "SECRET") {
			t.Fatalf("leak in %s: %s", x.Name, x.Value)
		}
	}
	if h[0].Value != "a={cookie:a}; b={cookie:b}" || h[1].Value != "a={cookie:a}; Path=/; HttpOnly" || h[2].Value != "Bearer {header:authorization}" || h[3].Value != "*/*" {
		t.Fatalf("unexpected: %+v", h)
	}
}

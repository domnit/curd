package redact

import (
	"fmt"
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

func TestEncodedVariants(t *testing.T) {
	const secret = "ab/cd+ef==SECRETTOKEN"
	r := New(Secret{secret, "{cookie:s}"})
	inputs := map[string]string{
		"lowercase pct":      "https://a.com/x?t=ab%2fcd%2bef%3d%3dSECRETTOKEN&n=1",
		"uppercase pct":      "https://a.com/x?t=ab%2Fcd%2Bef%3D%3DSECRETTOKEN",
		"mixed-case pct":     "?t=ab%2Fcd%2bef%3D%3dSECRETTOKEN",
		"partially escaped":  "?t=ab/cd%2Bef==SECRETTOKEN",
		"json slash":         `{"t":"ab\/cd+ef==SECRETTOKEN"}`,
		"json html escapes":  `{"t":"ab\/cd+ef==SECRETTOKEN"}`,
		"json all u escapes": `{"t":"` + uesc(secret, "%04x") + `"}`,
		"json upper u":       `{"t":"` + uesc(secret, "%04X") + `"}`,
		"double encoded":     "?t=ab%252Fcd%252Bef%253D%253DSECRETTOKEN",
	}
	for name, in := range inputs {
		if got := r.String(in); strings.Contains(got, "SECRETTOKEN") || strings.Contains(got, "SECRET") {
			t.Errorf("%s: leak: %s", name, got)
		}
	}
	sp := New(Secret{"has space SECRETTOKEN", "{cookie:sp}"})
	for _, in := range []string{"q=has+space+SECRETTOKEN", "q=has%20space%20SECRETTOKEN"} {
		if got := sp.String(in); strings.Contains(got, "SECRETTOKEN") {
			t.Errorf("space form leak: %s", got)
		}
	}
	html := New(Secret{"a<b>&cSECRETTOKEN", "{cookie:h}"})
	if got := html.String(`{"v":"a<b>&cSECRETTOKEN"}`); strings.Contains(got, "SECRETTOKEN") {
		t.Errorf("html-escaped json leak: %s", got)
	}
	// Unrelated text with percent signs and escapes is left alone.
	plain := `{"u":"a%2Fb","s":"x\/y"} 100% done`
	if got := r.String(plain); got != plain {
		t.Errorf("unrelated text changed: %s", got)
	}
}

func uesc(s, f string) string {
	var b strings.Builder
	for _, c := range s {
		b.WriteString(`\u` + fmt.Sprintf(f, c))
	}
	return b.String()
}

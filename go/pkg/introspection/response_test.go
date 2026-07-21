package introspection

import (
	"encoding/json"
	"testing"
)

// RFC 7662 §2.2 (via RFC 7519 §4.1.3): aud may be a single string or an array
// of strings; both decode into the Audience slice.
func TestAudience_FlexibleDecode(t *testing.T) {
	tests := []struct {
		name string
		body string
		want []string
	}{
		{"single string", `{"active":true,"aud":"https://api.example.com"}`, []string{"https://api.example.com"}},
		{"array", `{"active":true,"aud":["a","b","c"]}`, []string{"a", "b", "c"}},
		{"absent", `{"active":true}`, nil},
		{"null", `{"active":true,"aud":null}`, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var ir Introspection
			if err := json.Unmarshal([]byte(tt.body), &ir); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if len(ir.Aud) != len(tt.want) {
				t.Fatalf("aud = %v, want %v", ir.Aud, tt.want)
			}
			for i := range tt.want {
				if ir.Aud[i] != tt.want[i] {
					t.Errorf("aud[%d] = %q, want %q", i, ir.Aud[i], tt.want[i])
				}
			}
		})
	}
}

// A malformed aud (number, or array with a non-string element) is a decode
// error, not silently dropped.
func TestAudience_RejectsMalformed(t *testing.T) {
	for _, body := range []string{
		`{"active":true,"aud":42}`,
		`{"active":true,"aud":["ok",null]}`,
		`{"active":true,"aud":[1,2]}`,
	} {
		var ir Introspection
		if err := json.Unmarshal([]byte(body), &ir); err == nil {
			t.Errorf("expected decode error for aud in %s", body)
		}
	}
}

// Contains reports audience membership.
func TestAudience_Contains(t *testing.T) {
	a := Audience{"one", "two"}
	if !a.Contains("two") {
		t.Error("Contains(two) = false")
	}
	if a.Contains("three") {
		t.Error("Contains(three) = true")
	}
}

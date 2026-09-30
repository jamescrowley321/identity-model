//go:build integration

package conformance

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/jamescrowley321/identity-model/go/pkg/userinfo"
)

// runUserInfoVector is the userinfo.json adapter: userinfo.Fetch.
func runUserInfoVector(t *testing.T, label, base string, v HTTPVector) {
	t.Helper()

	opts := []userinfo.Option{userinfo.WithInsecureAllowHTTP()}
	if sub, ok := v.Input["expected_sub"].(string); ok {
		opts = append(opts, userinfo.WithSubjectValidation(sub))
	}
	ui, err := userinfo.Fetch(context.Background(), base+"/userinfo", inputString(v, "token"), opts...)

	switch v.Expect.Outcome {
	case OutcomeAccept:
		if err != nil {
			t.Fatalf("%s: expected accept, got %v", label, err)
		}
		typed := typedUserInfoClaims(t, ui)
		for name, want := range v.Expect.Claims {
			have, ok := typed[name]
			if !ok {
				t.Errorf("%s: claim %s is not a typed field", label, name)
			} else if !reflect.DeepEqual(have, want) {
				t.Errorf("%s: typed claim %s = %v, want %v", label, name, have, want)
			}
		}
		for name, want := range v.Expect.CustomClaims {
			if have := ui.Claims()[name]; !reflect.DeepEqual(have, want) {
				t.Errorf("%s: claim map %s = %v, want %v", label, name, have, want)
			}
		}
	case OutcomeReject:
		switch v.Expect.Error {
		case "":
		case "subject_mismatch":
			var sm *userinfo.SubjectMismatchError
			if !errors.As(err, &sm) {
				t.Fatalf("%s: expected SubjectMismatchError, got %v", label, err)
			}
			return
		case "missing_sub":
			var re *userinfo.RequestError
			if !errors.As(err, &re) || !strings.Contains(err.Error(), "missing sub") {
				t.Fatalf("%s: expected missing-sub RequestError, got %v", label, err)
			}
			return
		default:
			t.Fatalf("%s: unknown expected error %q", label, v.Expect.Error)
		}
		var ue *userinfo.UserInfoError
		if !errors.As(err, &ue) {
			t.Fatalf("%s: expected UserInfoError, got %v", label, err)
		}
		if ue.StatusCode != v.Expect.Status {
			t.Errorf("%s: status = %d, want %d", label, ue.StatusCode, v.Expect.Status)
		}
		if ue.WWWAuthenticate != v.Expect.WWWAuthenticate {
			t.Errorf("%s: WWW-Authenticate = %q, want %q", label, ue.WWWAuthenticate, v.Expect.WWWAuthenticate)
		}
	default:
		t.Fatalf("%s: unknown expected outcome %q", label, v.Expect.Outcome)
	}
}

// typedUserInfoClaims maps the typed §5.1 fields back to claim names, as JSON
// values, so they compare against the vector's claims.
func typedUserInfoClaims(t *testing.T, ui *userinfo.UserInfoResponse) map[string]any {
	t.Helper()
	b, err := json.Marshal(map[string]any{
		"sub":                   ui.Sub,
		"name":                  ui.Name,
		"given_name":            ui.GivenName,
		"family_name":           ui.FamilyName,
		"middle_name":           ui.MiddleName,
		"nickname":              ui.Nickname,
		"preferred_username":    ui.PreferredUsername,
		"profile":               ui.Profile,
		"picture":               ui.Picture,
		"website":               ui.Website,
		"email":                 ui.Email,
		"email_verified":        ui.EmailVerified,
		"gender":                ui.Gender,
		"birthdate":             ui.Birthdate,
		"zoneinfo":              ui.Zoneinfo,
		"locale":                ui.Locale,
		"phone_number":          ui.PhoneNumber,
		"phone_number_verified": ui.PhoneNumberVerified,
		"address":               ui.Address,
		"updated_at":            ui.UpdatedAt,
	})
	if err != nil {
		t.Fatalf("marshal typed claims: %v", err)
	}
	var out map[string]any
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("unmarshal typed claims: %v", err)
	}
	return out
}

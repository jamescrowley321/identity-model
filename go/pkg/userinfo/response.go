package userinfo

import (
	"encoding/json"
	"fmt"
	"math"
)

// Address is the OIDC "address" claim, a structured postal address
// (OIDC Core 1.0 §5.1.1).
type Address struct {
	// Formatted is the full mailing address, formatted for display.
	Formatted string `json:"formatted,omitempty"`
	// StreetAddress is the street address component.
	StreetAddress string `json:"street_address,omitempty"`
	// Locality is the city or locality.
	Locality string `json:"locality,omitempty"`
	// Region is the state, province, prefecture, or region.
	Region string `json:"region,omitempty"`
	// PostalCode is the postal code.
	PostalCode string `json:"postal_code,omitempty"`
	// Country is the country name.
	Country string `json:"country,omitempty"`
}

// UserInfoResponse is the set of claims returned by the UserInfo endpoint
// (OIDC Core 1.0 §5.1). Standard claims are modelled as typed fields; any
// additional provider-specific or custom claims are preserved in the raw map
// accessible via [UserInfoResponse.Claims].
type UserInfoResponse struct {
	// Sub is the subject identifier (always present, §5.3.2).
	Sub string
	// Name is the end-user's full name.
	Name string
	// GivenName is the given (first) name.
	GivenName string
	// FamilyName is the family (last) name.
	FamilyName string
	// MiddleName is the middle name.
	MiddleName string
	// Nickname is the casual name.
	Nickname string
	// PreferredUsername is the shorthand name the end-user prefers.
	PreferredUsername string
	// Profile is the URL of the end-user's profile page.
	Profile string
	// Picture is the URL of the end-user's profile picture.
	Picture string
	// Website is the URL of the end-user's web page or blog.
	Website string
	// Email is the preferred e-mail address.
	Email string
	// EmailVerified reports whether the e-mail has been verified. It is a
	// pointer so that an absent claim (nil) is distinguishable from an
	// explicit false.
	EmailVerified *bool
	// Gender is the end-user's gender.
	Gender string
	// Birthdate is the birthday, "YYYY-MM-DD" or "YYYY".
	Birthdate string
	// Zoneinfo is the time-zone, e.g. "Europe/Paris".
	Zoneinfo string
	// Locale is the locale, e.g. "en-US".
	Locale string
	// PhoneNumber is the preferred telephone number.
	PhoneNumber string
	// PhoneNumberVerified reports whether the phone number has been verified.
	// It is a pointer so absent (nil) is distinguishable from explicit false.
	PhoneNumberVerified *bool
	// Address is the preferred postal address.
	Address *Address
	// UpdatedAt is the time the information was last updated, as seconds since
	// the Unix epoch.
	UpdatedAt int64

	// raw holds every claim returned (standard and custom), as decoded JSON
	// values, so callers can reach non-standard claims via Claims().
	raw map[string]any
}

// Claims returns the full set of claims returned by the endpoint, including any
// non-standard or provider-specific claims that are not modelled as typed
// fields. The returned map is the response's own backing map; callers must not
// mutate it.
func (r *UserInfoResponse) Claims() map[string]any {
	return r.raw
}

// UnmarshalJSON decodes a UserInfo response, stashing every claim in the raw
// map (so custom claims remain reachable via [UserInfoResponse.Claims]) and
// routing the standard §5.1 claims to their typed fields.
func (r *UserInfoResponse) UnmarshalJSON(data []byte) error {
	if err := json.Unmarshal(data, &r.raw); err != nil {
		return err
	}

	// Decode the typed standard claims from the same bytes. Using an alias type
	// avoids recursing into this UnmarshalJSON, while a parallel struct keeps
	// the public field set free of json tags.
	var std struct {
		Sub                 string          `json:"sub"`
		Name                string          `json:"name"`
		GivenName           string          `json:"given_name"`
		FamilyName          string          `json:"family_name"`
		MiddleName          string          `json:"middle_name"`
		Nickname            string          `json:"nickname"`
		PreferredUsername   string          `json:"preferred_username"`
		Profile             string          `json:"profile"`
		Picture             string          `json:"picture"`
		Website             string          `json:"website"`
		Email               string          `json:"email"`
		EmailVerified       *bool           `json:"email_verified"`
		Gender              string          `json:"gender"`
		Birthdate           string          `json:"birthdate"`
		Zoneinfo            string          `json:"zoneinfo"`
		Locale              string          `json:"locale"`
		PhoneNumber         string          `json:"phone_number"`
		PhoneNumberVerified *bool           `json:"phone_number_verified"`
		Address             *Address        `json:"address"`
		UpdatedAt           json.RawMessage `json:"updated_at"`
	}
	if err := json.Unmarshal(data, &std); err != nil {
		return fmt.Errorf("decode standard claims: %w", err)
	}

	updatedAt, err := parseUpdatedAt(std.UpdatedAt)
	if err != nil {
		return fmt.Errorf("decode updated_at: %w", err)
	}

	r.Sub = std.Sub
	r.Name = std.Name
	r.GivenName = std.GivenName
	r.FamilyName = std.FamilyName
	r.MiddleName = std.MiddleName
	r.Nickname = std.Nickname
	r.PreferredUsername = std.PreferredUsername
	r.Profile = std.Profile
	r.Picture = std.Picture
	r.Website = std.Website
	r.Email = std.Email
	r.EmailVerified = std.EmailVerified
	r.Gender = std.Gender
	r.Birthdate = std.Birthdate
	r.Zoneinfo = std.Zoneinfo
	r.Locale = std.Locale
	r.PhoneNumber = std.PhoneNumber
	r.PhoneNumberVerified = std.PhoneNumberVerified
	r.Address = std.Address
	r.UpdatedAt = updatedAt

	return nil
}

// parseUpdatedAt decodes the optional "updated_at" claim, defined by OIDC as a
// JSON number of seconds since the Unix epoch (§5.1). Some providers serialize
// it with a fractional or exponent part (e.g. 1.7e9); such a value is truncated
// to whole seconds rather than sinking the entire response decode and dropping
// every claim. An absent or null claim maps to 0. Values that cannot be
// represented as an int64 (overflow, Inf, NaN) are rejected so a crafted number
// cannot silently wrap to a garbage time.
func parseUpdatedAt(v json.RawMessage) (int64, error) {
	if len(v) == 0 || string(v) == "null" {
		return 0, nil
	}
	var n json.Number
	if err := json.Unmarshal(v, &n); err != nil {
		return 0, fmt.Errorf("expected number, got %s", v)
	}
	if i, err := n.Int64(); err == nil {
		return i, nil
	}
	if f, err := n.Float64(); err == nil {
		if math.IsInf(f, 0) || math.IsNaN(f) || f >= math.MaxInt64 || f < math.MinInt64 {
			return 0, fmt.Errorf("updated_at out of range: %v", f)
		}
		return int64(f), nil
	}
	return 0, fmt.Errorf("expected integer seconds, got %q", n.String())
}

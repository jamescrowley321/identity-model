// Package userinfo is a client for the OpenID Connect UserInfo endpoint
// (OpenID Connect Core 1.0 §5.3).
//
// [Fetch] GETs the userinfo_endpoint with an
// "Authorization: Bearer {accessToken}" header and decodes the response into a
// typed [UserInfoResponse]. Standard §5.1 claims are exposed as typed fields;
// any additional provider-specific claims remain reachable via
// [UserInfoResponse.Claims].
//
// Subject consistency: when the access token was obtained alongside an ID
// token, supply that ID token's "sub" with [WithSubjectValidation]. The
// UserInfo "sub" MUST match it (§5.3.2); a mismatch is reported as a
// [SubjectMismatchError], defending against token substitution.
//
// Errors are typed: a non-2xx response becomes a [UserInfoError] carrying the
// HTTP status and any WWW-Authenticate challenge; transport, decode, and
// configuration failures become a [RequestError]. All three match the package
// sentinels via errors.Is.
//
// Signed or encrypted UserInfo responses (application/jwt, §5.3.2) are out of
// scope and reported as a descriptive [RequestError]; this client handles the
// JSON serialization only.
//
// Example:
//
//	resp, err := userinfo.Fetch(ctx, cfg.UserInfoEndpoint, accessToken,
//		userinfo.WithSubjectValidation(idTokenSub))
//	if err != nil {
//		var ue *userinfo.UserInfoError
//		if errors.As(err, &ue) {
//			log.Printf("userinfo rejected (HTTP %d): %s", ue.StatusCode, ue.WWWAuthenticate)
//		}
//		return err
//	}
//	fmt.Println(resp.Sub, resp.Email, resp.Claims())
package userinfo

//! Example: mint a DPoP-bound access token (RFC 9449), then build the proof a
//! resource server would verify.
//!
//! DPoP sender-constrains a token to a key the client holds, so a stolen token
//! is useless without the private half. The flow has three moves:
//!
//! 1. generate a key pair and sign a proof for the token request;
//! 2. send the proof in the `DPoP` header — the authorization server returns
//!    `token_type: DPoP` and binds the token to the key's RFC 7638 thumbprint
//!    in `cnf.jkt`;
//! 3. for each resource request, sign a fresh proof carrying `ath` (the hash of
//!    the access token) and present the token as `Authorization: DPoP <token>`.
//!
//! The library does not attach the header for you yet
//! ([#573](https://github.com/jamescrowley321/identity-model/issues/573)), so
//! this example shows the two lines that do it — which is the whole of what the
//! forthcoming transport will automate.
//!
//! ## Configuration
//!
//! Every one of these is required, and every missing or unusable one exits
//! non-zero with a message naming it. The example never falls back to a
//! placeholder issuer and never reports success without completing the flow:
//! an example that exits 0 having demonstrated nothing is indistinguishable
//! from one that worked.
//!
//! | Variable | Meaning |
//! | --- | --- |
//! | `ISSUER` | The issuer identifier. Takes precedence over `TEST_DISCO_ADDRESS`. |
//! | `TEST_DISCO_ADDRESS` | An OIDC Discovery URL (`<issuer>/.well-known/openid-configuration`); the issuer is that URL minus the suffix. RFC 8414 §3.1 metadata URLs, which put the well-known segment *before* the issuer's path, cannot be reversed and are rejected — set `ISSUER` for those. |
//! | `TEST_CLIENT_ID` / `TEST_CLIENT_SECRET` | Client credentials. |
//! | `TEST_SCOPE` | Optional token scope. |
//! | `ALLOW_HTTP=1` | Explicit opt-in for a plaintext `http://` issuer. Local fixtures only; without it an `http://` issuer is refused rather than silently downgrading the transport. |
//!
//! ```text
//! make infra-up
//! set -a && . ./.env.node-oidc && set +a
//! cd rust && ALLOW_HTTP=1 cargo run --example dpop
//! ```

use reqwest::header::{HeaderMap, HeaderValue};
use rs_identity_model::{
    DiscoveryClient, DpopAlgorithm, DpopKey, DpopProofOptions, DpopVerifyOptions, TokenClient,
    dpop_ath, verify_proof,
};

/// OpenID Connect Discovery 1.0 §4: the metadata document lives at the issuer
/// with this appended — a *suffix*, which is why it can be stripped back off.
const WELL_KNOWN_SUFFIX: &str = "/.well-known/openid-configuration";

/// The discovery member that says the provider speaks DPoP (RFC 9449 §5.1).
const DPOP_ALGS_METADATA: &str = "dpop_signing_alg_values_supported";

/// Reads an environment variable, treating unset and empty as the same thing.
fn env_nonempty(name: &str) -> Option<String> {
    let value = std::env::var(name).ok()?;
    let value = value.trim().to_string();
    if value.is_empty() { None } else { Some(value) }
}

/// Resolves the issuer from `ISSUER`, else from `TEST_DISCO_ADDRESS`.
///
/// `strip_suffix` rather than `trim_end_matches`: the latter removes *every*
/// trailing repetition and, worse, silently removes nothing when the value is
/// not a discovery URL at all — which would hand `discover()` a metadata URL to
/// append `/.well-known/openid-configuration` to a second time. Returning the
/// miss makes each shape an explicit decision.
fn issuer_from_env() -> Result<String, String> {
    if let Some(issuer) = env_nonempty("ISSUER") {
        return Ok(trim_one_trailing_slash(&issuer));
    }

    let Some(disco) = env_nonempty("TEST_DISCO_ADDRESS") else {
        return Err(format!(
            "set ISSUER to the provider's issuer identifier, or TEST_DISCO_ADDRESS to its \
             discovery URL (<issuer>{WELL_KNOWN_SUFFIX}). For the local fixture: \
             `set -a && . ./.env.node-oidc && set +a`"
        ));
    };

    if let Some(issuer) = disco.strip_suffix(WELL_KNOWN_SUFFIX) {
        let issuer = trim_one_trailing_slash(issuer);
        if issuer.is_empty() {
            return Err(format!(
                "TEST_DISCO_ADDRESS={disco:?} is the well-known suffix with no issuer before it"
            ));
        }
        return Ok(issuer);
    }

    // RFC 8414 §3.1 inserts the well-known segment between the host and the
    // issuer's path (`https://host/.well-known/oauth-authorization-server/tenant`),
    // so the suffix is in the MIDDLE and no amount of trailing trimming recovers
    // the issuer. Only the OIDC Discovery form is supported here; say so rather
    // than pass a metadata URL through as an issuer.
    if disco.contains("/.well-known/") {
        return Err(format!(
            "TEST_DISCO_ADDRESS={disco:?} is a metadata URL this example cannot turn back into \
             an issuer: only the OIDC Discovery form <issuer>{WELL_KNOWN_SUFFIX} is supported, \
             and RFC 8414 §3.1 places the well-known segment before the issuer's path. \
             Set ISSUER explicitly."
        ));
    }

    // No well-known segment at all — the value is already an issuer.
    Ok(trim_one_trailing_slash(&disco))
}

/// Removes a single trailing `/`, the one OIDC Discovery §4 inserts before the
/// well-known suffix. Not `trim_end_matches`, which would eat every one.
fn trim_one_trailing_slash(value: &str) -> String {
    value.strip_suffix('/').unwrap_or(value).to_string()
}

/// Picks a proof algorithm both the provider and this crate support.
///
/// Presence of the metadata member is not enough: a provider advertising only
/// `RS256` will reject the `ES256` proof a hardcoded choice would sign, and the
/// rejection arrives as an opaque `invalid_dpop_proof` from the token endpoint.
fn select_algorithm(
    advertised: &serde_json::Value,
) -> Result<(DpopAlgorithm, Vec<String>), String> {
    let values = advertised.as_array().ok_or_else(|| {
        format!("{DPOP_ALGS_METADATA} is {advertised}, which is not the JSON array RFC 9449 §5.1 defines")
    })?;
    let names: Vec<String> = values
        .iter()
        .filter_map(|value| value.as_str().map(str::to_string))
        .collect();

    // First advertised match wins, so the provider's own preference order is
    // honoured rather than this example's.
    match names
        .iter()
        .find_map(|name| name.parse::<DpopAlgorithm>().ok())
    {
        Some(algorithm) => Ok((algorithm, names)),
        None => Err(format!(
            "provider advertises {DPOP_ALGS_METADATA}={names:?}; this crate signs DPoP proofs \
             with {} or {} only",
            DpopAlgorithm::Es256,
            DpopAlgorithm::Rs256
        )),
    }
}

/// Decides whether a plaintext issuer is allowed, from an explicit opt-in
/// rather than from the shape of the URL. Inferring it from the `http://`
/// prefix means any misconfigured issuer quietly downgrades its own transport.
fn allow_http_for(issuer: &str) -> Result<bool, String> {
    let opted_in = env_nonempty("ALLOW_HTTP").as_deref() == Some("1");
    if issuer.to_ascii_lowercase().starts_with("http://") && !opted_in {
        return Err(format!(
            "issuer {issuer} is plaintext http://, which would send the client secret and the \
             DPoP-bound token over an unencrypted link. Set ALLOW_HTTP=1 to opt in for a local \
             fixture, or use an https:// issuer."
        ));
    }
    Ok(opted_in)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let issuer = issuer_from_env()?;
    let (Some(client_id), Some(client_secret)) = (
        env_nonempty("TEST_CLIENT_ID"),
        env_nonempty("TEST_CLIENT_SECRET"),
    ) else {
        return Err(format!(
            "set TEST_CLIENT_ID and TEST_CLIENT_SECRET to mint a token from {issuer}"
        )
        .into());
    };
    let scope = env_nonempty("TEST_SCOPE");
    let allow_http = allow_http_for(&issuer)?;

    let discovery = DiscoveryClient::builder().allow_http(allow_http).build();
    let metadata = discovery.discover(&issuer).await?;

    // DPoP is optional, and a provider that supports it says so in discovery.
    // Sending a proof to one that does not simply leaves the token unbound, so
    // check before relying on the binding — and check which algorithms, not
    // merely that the member is there.
    let Some(advertised) = metadata.extra.get(DPOP_ALGS_METADATA) else {
        return Err(format!("provider {issuer} does not advertise {DPOP_ALGS_METADATA}").into());
    };
    let (algorithm, advertised) = select_algorithm(advertised)?;
    println!("provider supports DPoP proofs signed with {advertised:?}; using {algorithm}");

    // 1. The key pair. Generated here for one run; a real client persists it
    //    (`to_pkcs8_pem` / `from_pkcs8_pem`) so restarts do not invalidate
    //    tokens already bound to it.
    let key = DpopKey::generate(algorithm)?;
    let thumbprint = key.thumbprint()?;
    println!("key thumbprint (jkt) = {thumbprint}");

    // 2. The token-request proof. It covers the method and URI of the request
    //    it accompanies, and carries no `ath` — there is no access token yet.
    let proof = key.proof("POST", &metadata.token_endpoint, &DpopProofOptions::new())?;

    // This is the part the library does not do for you yet: put the proof in
    // the `DPoP` header of the token request. A client built per request keeps
    // each proof with the single request it was signed for.
    let mut headers = HeaderMap::new();
    headers.insert("DPoP", HeaderValue::from_str(&proof)?);
    let http = reqwest::Client::builder()
        .default_headers(headers)
        .build()?;

    let token = TokenClient::builder()
        .client_id(client_id)
        .client_secret(client_secret)
        .token_endpoint(&metadata.token_endpoint)
        .allow_http(allow_http)
        .http_client(http)
        .build()?
        .client_credentials(scope.as_deref())
        .await?;

    // RFC 9449 §5: a bound token comes back as `DPoP`, not `Bearer`. A `Bearer`
    // here means the proof was ignored and the token is NOT sender-constrained,
    // which is a failed run, not a caveat to print and move on from.
    println!("token_type = {}", token.token_type);
    if !token.token_type.eq_ignore_ascii_case("DPoP") {
        return Err(format!(
            "provider returned token_type {:?}: the proof was ignored and the token is an \
             ordinary bearer token, not sender-constrained",
            token.token_type
        )
        .into());
    }

    // 3. The resource-request proof: same key, the resource server's method and
    //    URI, plus `ath` binding it to this specific access token (§7).
    let resource_uri = metadata
        .userinfo_endpoint
        .clone()
        .unwrap_or_else(|| format!("{issuer}/resource"));
    println!("ath = {}", dpop_ath(&token.access_token));
    let resource_proof = key.proof(
        "GET",
        &resource_uri,
        &DpopProofOptions::new().access_token(&token.access_token),
    )?;

    println!("\nSend the protected-resource request as:");
    println!("  GET {resource_uri}");
    println!("  Authorization: DPoP {}", token.access_token);
    println!("  DPoP: {resource_proof}");

    // The other side of the wire, shown here so the check a resource server
    // owes is explicit. Verifying the proof is necessary but NOT sufficient:
    // the server must also confirm the proof's key is the key the token was
    // bound to, by comparing this thumbprint against the token's `cnf.jkt`.
    let verified = verify_proof(
        &resource_proof,
        "GET",
        &resource_uri,
        &DpopVerifyOptions::new().access_token(&token.access_token),
    )?;
    println!("\nresource server verified the proof:");
    println!("  jti        = {}", verified.jti);
    println!("  thumbprint = {}", verified.thumbprint);
    if verified.thumbprint != thumbprint {
        return Err(format!(
            "verified proof thumbprint {} is not the key the token was bound to ({thumbprint}) — \
             a resource server must reject this request",
            verified.thumbprint
        )
        .into());
    }
    println!("  binding    = matches the key the token was bound to");

    Ok(())
}

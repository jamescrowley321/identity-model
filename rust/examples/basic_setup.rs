//! Minimal example: imports the crate and exercises the public error type.
//! Run with: `cargo run --example basic_setup`

use rs_identity_model::IdentityError;

fn main() {
    let modules = ["discovery", "jwks", "jwt", "token", "userinfo"];
    println!("identity-model (Rust) — scaffolded.");
    println!("Modules: {}", modules.join(", "));

    // Demonstrate the unified error type that every capability returns.
    // JWT failures are typed variants: match on them, not on the message.
    let example: Result<(), IdentityError> = Err(IdentityError::Expired {
        exp: 1_700_000_000,
        now: 1_700_000_060,
    });
    match example {
        Err(IdentityError::Expired { exp, .. }) => {
            println!("Example error surface: token expired at {exp}");
        }
        Err(e) => println!("Example error surface: {e}"),
        Ok(()) => {}
    }
}

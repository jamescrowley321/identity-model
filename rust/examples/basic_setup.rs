//! Minimal example: imports the crate and exercises the public error type.
//! Run with: `cargo run --example basic_setup`

use identity_model::IdentityError;

fn main() {
    let modules = ["discovery", "jwks", "jwt", "token", "userinfo"];
    println!("identity-model (Rust) — scaffolded.");
    println!("Modules: {}", modules.join(", "));

    // Demonstrate the unified error type that every capability returns.
    let example: Result<(), IdentityError> =
        Err(IdentityError::Validation("example: token expired".into()));
    if let Err(e) = example {
        println!("Example error surface: {e}");
    }
}

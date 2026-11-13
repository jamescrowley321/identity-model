"""
Device Authorization Grant Example (RFC 8628)

Demonstrates the device authorization flow for devices with
limited input capabilities (CLIs, smart TVs, IoT devices).
"""

from py_identity_model import (
    DeviceAuthorizationRequest,
    DeviceTokenRequest,
)


def device_auth_example():
    """Demonstrate the device authorization flow."""
    print("\n" + "=" * 60)
    print("Device Authorization Grant (RFC 8628)")
    print("=" * 60)

    # Phase 1: Request device authorization
    device_auth_request = DeviceAuthorizationRequest(
        address="https://auth.example.com/device/authorize",
        client_id="cli-tool",
        scope="openid profile",
    )

    print(f"\n  Device auth endpoint: {device_auth_request.address}")
    print(f"  Client ID: {device_auth_request.client_id}")
    print(f"  Scope: {device_auth_request.scope}")
    print("  (Would call request_device_authorization())")
    print()

    # Simulate a successful response
    print("  Simulated response:")
    print("  User code: WDJB-MJHT")
    print("  Verification URL: https://auth.example.com/device")
    print("  Expires in: 1800 seconds")
    print("  Poll interval: 5 seconds")

    # Phase 2: Display instructions and poll
    print("\n  --- User Instructions ---")
    print("  1. Visit: https://auth.example.com/device")
    print("  2. Enter code: WDJB-MJHT")
    print("  3. Authorize the application")
    print("  --------------------------")

    # Phase 2: Polling pattern
    print("\n  Polling pattern (pseudocode):")
    print("  ```")
    print("  interval = response.interval or 5")
    print("  while True:")
    print("      time.sleep(interval)")
    print("      token_resp = poll_device_token(token_request)")
    print("      if token_resp.is_successful:")
    print("          access_token = token_resp.token['access_token']")
    print("          break")
    print("      elif token_resp.error_code == 'authorization_pending':")
    print("          continue  # keep polling")
    print("      elif token_resp.error_code == 'slow_down':")
    print("          interval += 5  # RFC 8628 §3.5: for this and all later polls")
    print("      else:")
    print("          break  # expired_token or access_denied")
    print("  ```")


def device_token_request_example():
    """Show how to construct a token polling request."""
    print("\n" + "=" * 60)
    print("Device Token Polling Request")
    print("=" * 60)

    token_request = DeviceTokenRequest(
        address="https://auth.example.com/token",
        client_id="cli-tool",
        device_code="GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS",
    )

    print(f"\n  Token endpoint: {token_request.address}")
    print(f"  Device code: {token_request.device_code[:20]}...")
    print("  (Would call poll_device_token() in a loop)")


def main():
    device_auth_example()
    device_token_request_example()
    print("\n" + "=" * 60)
    print("Examples completed!")
    print("=" * 60)


if __name__ == "__main__":
    main()

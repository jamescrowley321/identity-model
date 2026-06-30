import { generateKeyPair, exportJWK, decodeJwt } from "jose";
import Provider from "oidc-provider";
import crypto from "node:crypto";

const PORT = parseInt(process.env.PORT || "9000", 10);
if (Number.isNaN(PORT) || PORT < 1 || PORT > 65535) {
  console.error(`Invalid PORT: ${process.env.PORT} (must be 1-65535)`);
  process.exit(1);
}
const ISSUER = process.env.ISSUER || `http://localhost:${PORT}`;

// --- Key Generation ---

async function generateKeys() {
  const { privateKey: rsaPriv } = await generateKeyPair("RS256", {
    extractable: true,
  });
  const rsaJwk = {
    ...(await exportJWK(rsaPriv)),
    kid: "rsa-sig-key",
    use: "sig",
    alg: "RS256",
  };

  const { privateKey: ecPriv } = await generateKeyPair("ES256", {
    extractable: true,
  });
  const ecJwk = {
    ...(await exportJWK(ecPriv)),
    kid: "ec-sig-key",
    use: "sig",
    alg: "ES256",
  };

  return [rsaJwk, ecJwk];
}

// --- Static Account Store ---

const ACCOUNTS = {
  "test-user": {
    email: "test@example.com",
    email_verified: true,
    name: "Test User",
    given_name: "Test",
    family_name: "User",
  },
};

function findAccount(ctx, id) {
  const account = ACCOUNTS[id];
  if (!account) return undefined;
  return {
    accountId: id,
    async claims(use, scope) {
      return { sub: id, ...account };
    },
  };
}

// --- Provider Configuration ---

const ACCESS_TOKEN_TTL = 300;

async function startProvider() {
  const jwks = { keys: await generateKeys() };

  const configuration = {
    // Static clients
    clients: [
      {
        client_id: "test-client-credentials",
        client_secret: "test-client-credentials-secret",
        grant_types: [
          "client_credentials",
          "urn:ietf:params:oauth:grant-type:device_code",
          "urn:ietf:params:oauth:grant-type:token-exchange",
        ],
        response_types: [],
        scope: "openid api",
        token_endpoint_auth_method: "client_secret_basic",
      },
      {
        client_id: "test-auth-code",
        client_secret: "test-auth-code-secret",
        grant_types: ["authorization_code", "refresh_token"],
        response_types: ["code"],
        redirect_uris: ["http://localhost:8080/callback"],
        scope: "openid profile email offline_access api",
        token_endpoint_auth_method: "client_secret_basic",
      },
      {
        // Public client for pure PKCE testing (no client_secret)
        client_id: "test-pkce-public",
        grant_types: ["authorization_code", "refresh_token"],
        response_types: ["code"],
        redirect_uris: ["http://localhost:8080/callback"],
        scope: "openid profile email offline_access api",
        token_endpoint_auth_method: "none",
      },
      {
        client_id: "test-device",
        client_secret: "test-device-secret",
        grant_types: [
          "urn:ietf:params:oauth:grant-type:device_code",
          "refresh_token",
        ],
        response_types: [],
        scope: "openid api",
        token_endpoint_auth_method: "client_secret_basic",
      },
      {
        client_id: "test-token-exchange",
        client_secret: "test-token-exchange-secret",
        grant_types: ["urn:ietf:params:oauth:grant-type:token-exchange"],
        response_types: [],
        scope: "openid api",
        token_endpoint_auth_method: "client_secret_basic",
      },
      {
        // Client for introspection/revocation tests — issues opaque tokens
        // because defaultResource excludes this client (JWT tokens cannot
        // be introspected or revoked via oidc-provider's built-in endpoints).
        client_id: "test-opaque",
        client_secret: "test-opaque-secret",
        grant_types: ["client_credentials"],
        response_types: [],
        scope: "openid api",
        token_endpoint_auth_method: "client_secret_basic",
      },
      // FAPI 2.0 client deferred to T125 — requires private_key_jwt,
      // signed request objects, and PAR enforcement.
    ],

    // JWKS
    jwks,

    // Features
    features: {
      introspection: { enabled: true },
      revocation: { enabled: true },
      deviceFlow: {
        enabled: true,
        charset: "digits",
        userCodeInputSource: async (ctx, form, out, err) => {
          // NOTE: Raw HTML injection is intentional for this test fixture only.
          // Do not use this pattern in production code.
          if (err) {
            ctx.body = `<!DOCTYPE html><html><body>
              <h1>Device Login Error</h1>
              <p>${err.message || "An error occurred"}</p>
            </body></html>`;
            return;
          }
          ctx.body = `<!DOCTYPE html><html><body>
            <h1>Device Login</h1>
            <form method="POST" action="${ctx.oidc.urlFor("code_verification")}">
              ${form}
              <input type="text" name="user_code" placeholder="Enter code">
              <button type="submit">Submit</button>
            </form>
          </body></html>`;
        },
      },
      clientCredentials: { enabled: true },
      dPoP: { enabled: true },
      pushedAuthorizationRequests: { enabled: true },
      requestObjects: {
        request: true,
      },
      resourceIndicators: {
        enabled: true,
        // Default to urn:test:api so tokens are issued as JWTs.
        // This allows integration tests to validate tokens without
        // explicitly passing a resource parameter.
        // Exception: test-opaque client gets no resource → opaque tokens
        // for introspection/revocation testing.
        defaultResource: (ctx) => {
          if (ctx.oidc?.client?.clientId === "test-opaque") return undefined;
          return "urn:test:api";
        },
        getResourceServerInfo: (ctx, resourceIndicator) => {
          if (resourceIndicator !== "urn:test:api") {
            return undefined;
          }
          return {
            scope: "openid profile email api",
            accessTokenFormat: "jwt",
            accessTokenTTL: ACCESS_TOKEN_TTL,
            jwt: {
              sign: { alg: "RS256" },
            },
          };
        },
        useGrantedResource: () => true,
      },
      devInteractions: { enabled: true },
    },

    // Custom claims in access tokens (Descope-style multi-tenant claims)
    extraTokenClaims: async (ctx, token) => {
      if (token.kind === "AccessToken" || token.kind === "ClientCredentials") {
        return {
          dct: "test-tenant-1",
          tenants: {
            "test-tenant-1": {
              roles: ["admin"],
              permissions: ["projects.create", "projects.read"],
            },
            "test-tenant-2": {
              roles: ["viewer"],
              permissions: ["projects.read"],
            },
          },
        };
      }
      return {};
    },

    // Issue refresh tokens when offline_access scope is requested
    issueRefreshToken: async (ctx, client, code) => {
      if (!client.grantTypeAllowed("refresh_token")) {
        return false;
      }
      return (
        code.scopes.has("offline_access") ||
        (client.applicationType === "web" &&
          client.tokenEndpointAuthMethod !== "none")
      );
    },

    // Account lookup
    findAccount,

    // Scopes
    scopes: ["openid", "profile", "email", "offline_access", "api"],

    // Short TTLs for test speed
    ttl: {
      AccessToken: ACCESS_TOKEN_TTL,
      AuthorizationCode: 60,
      ClientCredentials: ACCESS_TOKEN_TTL,
      DeviceCode: 300,
      Grant: 600,
      IdToken: 300,
      Interaction: 600,
      RefreshToken: 600,
      Session: 900,
    },

    // Claims mapping
    claims: {
      openid: ["sub"],
      profile: ["name", "given_name", "family_name"],
      email: ["email", "email_verified"],
    },

    // Cookie keys for session management
    cookies: {
      keys: ["test-fixture-cookie-key-1", "test-fixture-cookie-key-2"],
    },

    // JWA algorithms — explicit for JAR and DPoP test coverage
    enabledJWA: {
      authorizationSigningAlgValues: ["RS256", "ES256"],
      requestObjectSigningAlgValues: ["RS256", "ES256"],
      dPoPSigningAlgValues: ["RS256", "ES256"],
      introspectionSigningAlgValues: ["RS256", "ES256"],
    },
  };

  const provider = new Provider(ISSUER, configuration);

  // Allow HTTP (non-TLS) for local test fixture
  provider.proxy = true;

  // --- Register Token Exchange Grant (RFC 8693) ---

  const grantType = "urn:ietf:params:oauth:grant-type:token-exchange";
  const parameters = new Set([
    "subject_token",
    "subject_token_type",
    "audience",
    "scope",
    "requested_token_type",
    "actor_token",
    "actor_token_type",
  ]);

  provider.registerGrantType(
    grantType,
    async function tokenExchangeHandler(ctx) {
      const {
        oidc: {
          params: {
            subject_token: subjectToken,
            subject_token_type: subjectTokenType,
          },
          client,
        },
      } = ctx;

      // Validate required parameters
      if (!subjectToken || !subjectTokenType) {
        ctx.body = {
          error: "invalid_request",
          error_description:
            "subject_token and subject_token_type are required",
        };
        ctx.status = 400;
        return;
      }

      // Validate subject_token_type (trim to handle whitespace edge case)
      const validTokenTypes = [
        "urn:ietf:params:oauth:token-type:access_token",
        "urn:ietf:params:oauth:token-type:jwt",
      ];
      if (!validTokenTypes.includes(subjectTokenType.trim())) {
        ctx.body = {
          error: "invalid_request",
          error_description: "unsupported subject_token_type",
        };
        ctx.status = 400;
        return;
      }

      // Validate subject_token — try opaque lookup first, then JWT decode
      let accountId = "test-user";
      const opaqueToken =
        (await provider.AccessToken.find(subjectToken).catch(() => null)) ||
        (await provider.ClientCredentials.find(subjectToken).catch(
          () => null,
        ));
      if (opaqueToken) {
        accountId = opaqueToken.accountId || "test-user";
      } else {
        // Try JWT format
        try {
          const decoded = decodeJwt(subjectToken);
          if (decoded.iss !== ISSUER) {
            ctx.body = {
              error: "invalid_grant",
              error_description:
                "subject_token was not issued by this provider",
            };
            ctx.status = 400;
            return;
          }
          if (decoded.exp && decoded.exp < Math.floor(Date.now() / 1000)) {
            ctx.body = {
              error: "invalid_grant",
              error_description: "subject_token has expired",
            };
            ctx.status = 400;
            return;
          }
          accountId = decoded.sub || "test-user";
        } catch {
          ctx.body = {
            error: "invalid_grant",
            error_description:
              "subject_token is invalid or not issued by this provider",
          };
          ctx.status = 400;
          return;
        }
      }

      // Issue a new access token
      const AccessToken = provider.AccessToken;
      const at = new AccessToken({
        accountId,
        client,
        scope: ctx.oidc.params.scope || "openid",
        grantId: ctx.oidc.uid || crypto.randomUUID(),
      });

      ctx.oidc.entity("AccessToken", at);
      const value = await at.save();
      const expiresIn = at.exp
        ? at.exp - Math.floor(Date.now() / 1000)
        : ACCESS_TOKEN_TTL;

      ctx.body = {
        access_token: value,
        issued_token_type: "urn:ietf:params:oauth:token-type:access_token",
        token_type: "Bearer",
        expires_in: expiresIn,
        scope: at.scope,
      };
    },
    parameters,
  );

  // Start listening
  const server = provider.listen(PORT, () => {
    console.log(
      `node-oidc-provider test fixture listening on ${ISSUER} (port ${PORT})`,
    );
    console.log(`Discovery: ${ISSUER}/.well-known/openid-configuration`);
    console.log(`JWKS: ${ISSUER}/jwks`);
  });

  server.on("error", (err) => {
    console.error(`Listen failed: ${err.message}`);
    process.exit(1);
  });

  // Graceful shutdown
  for (const signal of ["SIGTERM", "SIGINT"]) {
    process.on(signal, () => {
      console.log(`Received ${signal}, shutting down...`);
      server.close(() => process.exit(0));
    });
  }
}

startProvider().catch((err) => {
  console.error("Failed to start provider:", err);
  process.exit(1);
});

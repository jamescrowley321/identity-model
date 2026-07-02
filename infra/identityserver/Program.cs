using Duende.IdentityServer.Models;

var builder = WebApplication.CreateBuilder(args);

// Test fixture only: HTTP, in-memory stores, and a developer signing
// credential. Clients mirror infra/node-oidc-provider/provider.js so the
// same TEST_CLIENT_ID / TEST_CLIENT_SECRET work against both providers.
var issuer = Environment.GetEnvironmentVariable("ISSUER") ?? "http://localhost:9001";

var identityResources = new IdentityResource[]
{
    new IdentityResources.OpenId(),
    new IdentityResources.Profile(),
    new IdentityResources.Email(),
};

var apiScopes = new ApiScope[]
{
    new("api", "Test API"),
};

var apiResources = new ApiResource[]
{
    new("api", "Test API") { Scopes = { "api" } },
};

var clients = new Client[]
{
    new()
    {
        ClientId = "test-client-credentials",
        ClientSecrets = { new Secret("test-client-credentials-secret".Sha256()) },
        AllowedGrantTypes = GrantTypes.ClientCredentials,
        AllowedScopes = { "api" },
        AccessTokenLifetime = 300,
    },
    new()
    {
        ClientId = "test-auth-code",
        ClientSecrets = { new Secret("test-auth-code-secret".Sha256()) },
        AllowedGrantTypes = GrantTypes.Code,
        RequirePkce = true,
        AllowedScopes = { "openid", "profile", "email", "api" },
        RedirectUris = { "http://localhost:8080/callback" },
        AllowOfflineAccess = true,
        AccessTokenLifetime = 300,
    },
    new()
    {
        ClientId = "test-pkce-public",
        RequireClientSecret = false,
        AllowedGrantTypes = GrantTypes.Code,
        RequirePkce = true,
        AllowedScopes = { "openid", "profile", "email", "api" },
        RedirectUris = { "http://localhost:8080/callback" },
        AllowOfflineAccess = true,
        AccessTokenLifetime = 300,
    },
};

builder.Services.AddIdentityServer(options => { options.IssuerUri = issuer; })
    .AddInMemoryIdentityResources(identityResources)
    .AddInMemoryApiScopes(apiScopes)
    .AddInMemoryApiResources(apiResources)
    .AddInMemoryClients(clients)
    .AddDeveloperSigningCredential();

var app = builder.Build();

app.UseIdentityServer();

await app.RunAsync();

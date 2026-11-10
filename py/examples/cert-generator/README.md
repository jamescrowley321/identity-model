# Certificate Generator

This container generates self-signed SSL/TLS certificates for local development and testing.

## What It Does

1. **Creates a Certificate Authority (CA)**
   - Generates a private key (`ca-key.pem`)
   - Creates a self-signed CA certificate (`ca-cert.crt`)

2. **Generates Server Certificates**
   - Creates a server private key (`aspnetapp.key`)
   - Generates a Certificate Signing Request (CSR)
   - Signs the server certificate with the CA (`aspnetapp.crt`)
   - Creates a PFX bundle for ASP.NET Core (`aspnetapp.pfx`)

3. **Configures Subject Alternative Names (SAN)**
   - DNS: `$CERT_HOSTNAME` (default `identityserver`)
   - DNS: localhost
   - IP: 127.0.0.1

## Usage

The certificate generator runs automatically when starting the Docker Compose stack (from `py/examples/`):

```bash
docker compose -f docker-compose.test.yml up
```

### Environment Variables

- `CERT_HOSTNAME` - The hostname for the certificate (default: `identityserver`)
- `CERT_DAYS` - Certificate validity period in days (default: `365`)
- `CERT_PASSWORD` - Password for the PFX file (script default: `password`; `docker-compose.test.yml` passes `${CERT_PASSWORD:-SuperSecurePassword123!}`, so override it via the environment or a `.env` file)

### Certificate Reuse

Certificates are stored in a Docker volume and reused across container restarts. To regenerate:

```bash
docker volume rm examples_shared-certs
docker compose -f docker-compose.test.yml up --build
```

## Output Files

All files are created in `/certs` (mounted as a Docker volume):

- `ca-cert.crt` - CA certificate (distribute to clients)
- `ca-key.pem` - CA private key (keep secure)
- `aspnetapp.crt` - Server certificate
- `aspnetapp.key` - Server private key
- `aspnetapp.pfx` - PFX bundle for ASP.NET Core (password: configurable via `CERT_PASSWORD`)

## Security Notes

⚠️ **These certificates are for development/testing only!**

- Uses self-signed certificates
- Private keys are generated without passphrases (except PFX)
- Not suitable for production use
- Should only be used in trusted development environments

# Bake the realm export into the image rather than bind-mounting it. A single-file
# bind mount is unreliable across Docker backends (rootless / VM-backed daemons such
# as Rancher Desktop turn a not-yet-shared file path into an empty directory, so
# --import-realm silently imports nothing). COPY at build time is portable and mirrors
# the node-oidc-provider fixture's build-based approach.
FROM quay.io/keycloak/keycloak:26.3@sha256:357829ec7c4693397533035092ad13b0644bcc95ded311f33a3738c4d9e9bdba

COPY realm-export.json /opt/keycloak/data/import/realm-export.json

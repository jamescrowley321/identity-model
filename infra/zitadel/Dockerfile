# Provisioner for the Zitadel fixture (zitadel-setup in ../docker-compose.yml).
# The script is baked in rather than bind-mounted: single-file bind mounts are
# unreliable across Docker backends (see ../keycloak/Dockerfile).
FROM python:3.13-alpine@sha256:9ef1a599f863231c3d91e941389bfdc4a2d6070557243d54df1a4e57015b960e

COPY setup.py /setup.py
RUN mkdir /out
ENTRYPOINT ["python", "/setup.py"]

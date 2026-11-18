# One-shot setup: creates the app registration and writes deploy/cloud-locksmith.env.
# Build context is the repository root; deploy/ is bind-mounted at /out.
FROM mcr.microsoft.com/azure-cli:2.67.0

WORKDIR /setup
# The backend's own scope list, so the app registration and the backend cannot drift.
COPY backend/app/services/microsoft_oauth_scopes.py /setup/
COPY deploy/setup/cl_setup.py /setup/

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
ENTRYPOINT ["python3", "/setup/cl_setup.py"]

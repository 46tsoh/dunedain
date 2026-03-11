FROM python:3.12-slim

# Install Trivy (container/filesystem vulnerability scanner)
# https://github.com/aquasecurity/trivy
RUN apt-get update && apt-get install -y --no-install-recommends \
        wget ca-certificates \
    && wget -qO /tmp/trivy.tar.gz \
        "https://github.com/aquasecurity/trivy/releases/download/v0.69.3/trivy_0.69.3_Linux-64bit.tar.gz" \
    && tar -xzf /tmp/trivy.tar.gz -C /usr/local/bin trivy \
    && rm /tmp/trivy.tar.gz \
    && apt-get purge -y wget \
    && rm -rf /var/lib/apt/lists/*

# Install Grype (alternative OSS scanner by Anchore)
# https://github.com/anchore/grype
RUN apt-get update && apt-get install -y --no-install-recommends curl \
    && curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh \
        | sh -s -- -b /usr/local/bin v0.109.0 \
    && apt-get purge -y curl \
    && rm -rf /var/lib/apt/lists/*

# Install Syft (SBOM generator by Anchore — used for registry-native scanning)
# https://github.com/anchore/syft
RUN apt-get update && apt-get install -y --no-install-recommends curl \
    && curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh \
        | sh -s -- -b /usr/local/bin v1.21.0 \
    && apt-get purge -y curl \
    && rm -rf /var/lib/apt/lists/*

# Install osv-scanner (Google OSV vulnerability scanner)
# https://github.com/google/osv-scanner
RUN apt-get update && apt-get install -y --no-install-recommends wget ca-certificates \
    && wget -qO /usr/local/bin/osv-scanner \
        "https://github.com/google/osv-scanner/releases/download/v2.3.3/osv-scanner_linux_amd64" \
    && chmod +x /usr/local/bin/osv-scanner \
    && apt-get purge -y wget \
    && rm -rf /var/lib/apt/lists/*

# Install Docker CLI (client only — needed by osv-scanner scan image)
# No daemon is started; the binary is only used to pull images for osv-scanner.
RUN apt-get update && apt-get install -y --no-install-recommends \
        apt-transport-https ca-certificates curl gnupg lsb-release \
    && install -m 0755 -d /etc/apt/keyrings \
    && curl -fsSL https://download.docker.com/linux/debian/gpg \
        | gpg --dearmor -o /etc/apt/keyrings/docker.gpg \
    && chmod a+r /etc/apt/keyrings/docker.gpg \
    && echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
        https://download.docker.com/linux/debian $(. /etc/os-release && echo "$VERSION_CODENAME") stable" \
        > /etc/apt/sources.list.d/docker.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends docker-ce-cli \
    && apt-get purge -y curl gnupg lsb-release apt-transport-https \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
EXPOSE 1337
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "1337"]

FROM python:3.11-slim


ARG TERRAFORM_VERSION=1.14.4

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    git \
    openssh-client \
    curl \
    unzip \
    gnupg \
    ca-certificates \
    apt-transport-https \
    lsb-release \
    && rm -rf /var/lib/apt/lists/*

# Install Terraform (detect architecture and install appropriate version)
RUN ARCH=$(uname -m) && \
    if [ "$ARCH" = "aarch64" ] || [ "$ARCH" = "arm64" ]; then \
        curl -s https://releases.hashicorp.com/terraform/${TERRAFORM_VERSION}/terraform_${TERRAFORM_VERSION}_linux_arm64.zip -o terraform.zip; \
    else \
        curl -s https://releases.hashicorp.com/terraform/${TERRAFORM_VERSION}/terraform_${TERRAFORM_VERSION}_linux_amd64.zip -o terraform.zip; \
    fi && \
    unzip terraform.zip && \
    mv terraform /usr/local/bin/ && \
    rm -rf terraform.zip

# Install AWS CLI (detect architecture and install appropriate version)
RUN ARCH=$(uname -m) && \
    if [ "$ARCH" = "aarch64" ] || [ "$ARCH" = "arm64" ]; then \
        curl "https://awscli.amazonaws.com/awscli-exe-linux-aarch64.zip" -o "awscliv2.zip"; \
    else \
        curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"; \
    fi && \
    unzip awscliv2.zip && \
    ./aws/install && \
    rm -rf awscliv2.zip aws

# Install Azure CLI
RUN curl -sL https://aka.ms/InstallAzureCLIDeb | bash

# Install Google Cloud SDK
RUN echo "deb [signed-by=/usr/share/keyrings/cloud.google.gpg] https://packages.cloud.google.com/apt cloud-sdk main" | tee -a /etc/apt/sources.list.d/google-cloud-sdk.list && \
    curl https://packages.cloud.google.com/apt/doc/apt-key.gpg | gpg --dearmor -o /usr/share/keyrings/cloud.google.gpg && \
    apt-get update && \
    apt-get install -y google-cloud-cli && \
    rm -rf /var/lib/apt/lists/*

# Install Ludus CLI (if available for the architecture)
RUN ARCH=$(uname -m) && \
    if [ "$ARCH" = "aarch64" ] || [ "$ARCH" = "arm64" ]; then \
        curl -sL -o /usr/local/bin/ludus "https://gitlab.com/badsectorlabs/ludus/-/releases/permalink/latest/downloads/ludus-client_linux-arm64" 2>/dev/null || true; \
    else \
        curl -sL -o /usr/local/bin/ludus "https://gitlab.com/badsectorlabs/ludus/-/releases/permalink/latest/downloads/ludus-client_linux-amd64" 2>/dev/null || true; \
    fi && \
    if [ -f /usr/local/bin/ludus ]; then chmod +x /usr/local/bin/ludus; fi

# Copy requirements file
COPY requirements.txt /app/requirements.txt

# Install Python dependencies
RUN pip install --no-cache-dir -r /app/requirements.txt

# Copy application files
COPY api/ /app/api/
COPY attack_range/ /app/attack_range/
COPY templates/ /app/templates/
COPY terraform/ /app/terraform/

# Create config and ssh_keys directories
RUN mkdir -p /app/config /app/ssh_keys

# Set environment variables
ENV PYTHONPATH=/app
ENV FLASK_APP=api/app.py
ENV OBJC_DISABLE_INITIALIZE_FORK_SAFETY=YES

# Expose port
EXPOSE 4000

# Run the application
CMD ["python", "api/app.py"]

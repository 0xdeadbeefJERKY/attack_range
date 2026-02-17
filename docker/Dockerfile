FROM ubuntu:22.04
ENV DEBIAN_FRONTEND=noninteractive

ARG TERRAFORM_VERSION=1.14.4
RUN apt-get update && \
    apt-get install -y --no-install-recommends software-properties-common gnupg && \
    add-apt-repository ppa:deadsnakes/ppa && \
    apt-get update && \
    apt-get install -y --no-install-recommends \
        python3.12 \
        git \
        unzip \
        curl \
        vim \
        apt-transport-https \
        ca-certificates \
        lsb-release && \
    rm -rf /var/lib/apt/lists/*

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

# Install Ludus CLI from GitLab package registry
RUN ARCH=$(uname -m) && \
    if [ "$ARCH" = "aarch64" ] || [ "$ARCH" = "arm64" ]; then \
        LUDUS_ARCH="arm64"; \
    else \
        LUDUS_ARCH="amd64"; \
    fi && \
    LUDUS_PROJECT_ID=54052321 && \
    LUDUS_TAG=$(curl -sL "https://gitlab.com/api/v4/projects/${LUDUS_PROJECT_ID}/repository/tags" | python3 -c "import sys,json; print(json.load(sys.stdin)[0]['name'])" 2>/dev/null) && \
    if [ -n "$LUDUS_TAG" ]; then \
        curl -sL -o /usr/local/bin/ludus \
            "https://gitlab.com/api/v4/projects/${LUDUS_PROJECT_ID}/packages/generic/ludus/${LUDUS_TAG}/ludus-client_linux-${LUDUS_ARCH}-${LUDUS_TAG}" && \
        chmod +x /usr/local/bin/ludus; \
    fi

RUN echo 'alias python=python3.12' >> ~/.bashrc

RUN curl https://bootstrap.pypa.io/get-pip.py -o get-pip.py && \
    python3.12 get-pip.py && \
    rm get-pip.py
RUN python3.12 -m pip install --upgrade setuptools wheel

RUN python3.12 -m pip install --upgrade pip

WORKDIR /attack_range

COPY . /attack_range

# Remove system-installed blinker package files to avoid uninstall conflict
RUN rm -rf /usr/lib/python3/dist-packages/blinker* /usr/local/lib/python3.12/dist-packages/blinker* 2>/dev/null || true

# Install all requirements
RUN python3.12 -m pip install --break-system-packages -r requirements.txt

ENTRYPOINT ["python3.12", "attack_range.py"]

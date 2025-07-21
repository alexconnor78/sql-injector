FROM python:3.10-slim

# Install dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    git \
    curl \
    libreadline-dev \
    vim \
    net-tools \
    chromium \
    chromium-driver && \
    rm -rf /var/lib/apt/lists/*

# Create workspace structure
RUN mkdir -p /workspace/{src,targets,output}

# Set working directory
WORKDIR /workspace

# Default command (can be overridden)
CMD ["bash"]
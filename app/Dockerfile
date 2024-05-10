# Use Python 3.11 slim image as the base
FROM python:3.11-slim

# Set environment variables to prevent Python from writing pyc files to disc (unbuffered mode)
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

# Set work directory
WORKDIR /opt/copilot/app

# Install system dependencies including build tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    apt-transport-https \
    ca-certificates \
    curl \
    gnupg \
    lsb-release \
    gcc \
    libc6-dev \
    && rm -rf /var/lib/apt/lists/*

# Optionally, after building wheels you could uninstall build dependencies to keep the image slim
# This step is optional and can be adjusted based on your needs

# Copy the requirements file and install Python dependencies
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Copy your application into the Docker image
COPY . .

# Environment variables for Cryptolens (as in the original Dockerfile)
ARG CRYPTOLENS_KEY
ENV CRYPTOLENS_KEY=${CRYPTOLENS_KEY}

ARG CRYPTOLENS_PRODUCT_ID
ENV CRYPTOLENS_PRODUCT_ID=${CRYPTOLENS_PRODUCT_ID}

# Run your application
CMD ["sh", "-c", "ls -la && python module.py"]

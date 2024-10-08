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

# Obfuscate all .py files in the directory
RUN pyarmor gen --platform linux.x86_64 .

# Copy all non-Python files to the dist directory
RUN find . -type f ! -name "*.py" -exec cp --parents \{\} dist \;

# Remove everything but the dist directory
RUN find . ! -path "./dist*" -delete

# Run your application
CMD ["sh", "-c", "ls -la && python dist/module.py"]

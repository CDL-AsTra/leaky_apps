# Use the latest Ubuntu LTS
FROM ubuntu:24.04

# Set non-interactive mode for apt
ENV DEBIAN_FRONTEND=noninteractive

# Update & install system dependencies
RUN apt-get update && \
    apt-get install -y \
        python3 \
        python3-pip \
        python3-venv \
        exiftool \
        wget \
        unzip \
        openjdk-17-jre \
        libmagic1

# Install jadx-gui (latest stable)
RUN mkdir -p /opt/jadx && \
    wget https://github.com/skylot/jadx/releases/download/v1.5.2/jadx-1.5.2.zip -O /tmp/jadx.zip && \
    unzip /tmp/jadx.zip -d /opt/jadx && \
    rm /tmp/jadx.zip

# Add jadx to PATH
ENV PATH="/opt/jadx/bin:${PATH}"

# Copy your Python code to /workspace
RUN mkdir -p /analysis/
COPY ./suffix_classes.py /analysis/
COPY ./config_parsing.py /analysis/
COPY ./analysis.py /analysis/
COPY ./references/ /analysis/references/
COPY  ./requirements.txt /analysis/

# copy run_all.py script
COPY ./docker/run_all.py /analysis/run_all.py

# Copy trufflehog
COPY ./docker/trufflehog /usr/local/bin/trufflehog
RUN chmod +x /usr/local/bin/trufflehog


# Copy verify scripts
COPY ./verify/ /analysis/verify/

# Install Python dependencies
RUN pip install -r /analysis/requirements.txt --break-system-packages


# Set working directory
WORKDIR /analysis/



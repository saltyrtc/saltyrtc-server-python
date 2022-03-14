FROM python:3.7-slim

# Install dependencies
RUN apt-get update -qqy \
 && apt-get install -qqy --no-install-recommends \
    libsodium23 \
 && rm -rf /var/lib/apt/lists/* /var/cache/apt/*

# Set working directory
WORKDIR /srv/saltyrtc

# Copy sources
COPY examples ./examples
COPY saltyrtc ./saltyrtc
COPY tests ./tests
COPY CHANGELOG.rst LICENSE README.rst setup.cfg setup.py ./

# Install the server
RUN pip install --no-cache-dir ".[logging, uvloop]"

# Create 'saltyrtc' user and use it
RUN useradd -d /srv/saltyrtc -M -s /sbin/nologin -U saltyrtc
USER saltyrtc

# Define server as entrypoint
ENTRYPOINT ["/usr/local/bin/saltyrtc-server"]

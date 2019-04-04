# Dockerfile for the SaltyRTC Server, based on the python:3 image.
#
# WARNING: This Dockerfile does not include TLS termination. Make sure to run
#          the container behind a reverse proxy (e.g. Nginx) or make use of
#          the -tc and -tk parameters to provide the certificate and key
#          directly.
FROM python:3

# Install dependencies
RUN apt-get update -qqy \
 && apt-get install -qqy --no-install-recommends \
    libsodium18 \
 && rm -rf /var/lib/apt/lists/* /var/cache/apt/*

# Set working directory
WORKDIR /usr/src/saltyrtc-server

# Copy sources
COPY examples ./examples
COPY saltyrtc ./saltyrtc
COPY tests ./tests
COPY CHANGELOG.rst LICENSE README.rst setup.cfg setup.py ./

# Install the server
RUN pip install --no-cache-dir ".[logging, uvloop]"

# Define server as entrypoint
ENTRYPOINT ["/usr/local/bin/saltyrtc-server"]

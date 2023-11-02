FROM postgres:latest@sha256:d8048a55b0952189c0f6fcc89ec46d78e1b56ac25eae0b2b85e449a57aa0ce44
COPY docker-healthcheck.sh /usr/local/bin/
HEALTHCHECK CMD ["docker-healthcheck.sh"]

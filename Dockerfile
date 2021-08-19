ARG NEXUS_VERSION=3.33.0
FROM sonatype/nexus3:${NEXUS_VERSION}

ARG PROJECT_NAME=nexus3-jwt-auth-plugin
USER root
COPY ./target/${PROJECT_NAME}-*.kar /opt/sonatype/nexus/deploy
USER nexus

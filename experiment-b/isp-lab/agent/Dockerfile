FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends snmpd ca-certificates && rm -rf /var/lib/apt/lists/*
COPY startup.sh /usr/local/bin/startup.sh
RUN chmod 700 /usr/local/bin/startup.sh
EXPOSE 161/udp
ENTRYPOINT ["/usr/local/bin/startup.sh"]

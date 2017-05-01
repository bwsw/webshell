FROM debian:jessie

MAINTAINER Bitworks Software info@bitworks.software

EXPOSE 80

ENV SSH_PORT 22
ENV USERNAME root
ENV DEFAULT_IP 0.0.0.0
ENV ALLOWED_NETWORKS 10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,fc00::/7
ENV INACTIVITY_INTERVAL 60
ENV VAULT_URL http://127.0.0.1:8200/
ENV VAULT_ENABLED false
ENV VAULT_VALUE	pri

RUN echo 'debconf debconf/frontend select Noninteractive' | debconf-set-selections
RUN DEBIAN_FRONTEND=noninteractive apt-get update
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y -q python3 shellinabox strace ssh
RUN useradd -ms /bin/bash webshell

COPY ./shellinabox.py /opt
COPY ./shellinabox.init /opt
RUN  chmod 755 /opt/shellinabox.py /opt/shellinabox.init

CMD ["/opt/shellinabox.init"]

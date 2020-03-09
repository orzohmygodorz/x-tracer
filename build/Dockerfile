FROM orzohmygodorz/x-agent-env:latest
LABEL maintainer="Jace Liang <b436412@gmail.com>"

#RUN set -ex; \
#  echo "deb [trusted=yes] http://repo.iovisor.org/apt/bionic bionic-nightly main" > /etc/apt/sources.list.d/iovisor.list; \
#  apt-get update -y; \
#  DEBIAN_FRONTEND=noninteractive apt-get install -y \
#    auditd \
#    bcc-tools \
#    libelf1 \
#    libbcc-examples \
#    software-properties-common; \
#  add-apt-repository ppa:longsleep/golang-backports; \
#  apt-get update -y; \
#  apt-get install golang-go -y;

COPY build/entrypoint.sh /
RUN chmod +x /entrypoint.sh
COPY pkg/tcptracer/tcptracer.bt /
COPY pkg/tcpconnlat/tcpconnlat.bt /
COPY bin/x-agent /
RUN chmod +x /x-agent

ENTRYPOINT ["/entrypoint.sh"]
CMD ["/x-agent"]

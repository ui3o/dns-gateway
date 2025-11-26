FROM docker.io/golang:1.24.10-trixie AS builder

COPY ./src /app/src
WORKDIR /app/src
RUN GOOS=linux go build -o dns-gateway .

FROM docker.io/fedora:latest

RUN dnf upgrade -y && dnf install -y python3 make openssl

ENV GIN_MODE=release
EXPOSE 80/tcp 443/tcp 53/udp
COPY ./cert /opt/dns-gateway/cert
COPY ./conf /opt/dns-gateway/conf
COPY --from=builder /app/src/dns-gateway /opt/dns-gateway/dns-gateway
RUN chmod +x /opt/dns-gateway/dns-gateway && cd /opt/dns-gateway/cert && make gen_cert install_cert
WORKDIR /opt/dns-gateway
CMD ["/opt/dns-gateway/dns-gateway"]

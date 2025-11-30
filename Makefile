.PHONY: build setup-github-workspace run

print_cert:
	keytool -v -list -keystore certs/cacerts/keystore.jks -storepass changeit

setup-github-workspace:
	sudo apt-get update && sudo apt-get install -y podman golang openjdk-21-jre
	sudo mount --make-rshared /
	sudo ln -sf $(shell pwd)/dns-gateway /etc/dns-gateway

build:
	podman build -t dns-gateway:latest .

build-go:
	cd src && GOOS=linux go build -o dns-gateway .

run:
	podman kill local-dns-gateway || true
	podman create --rm --name local-dns-gateway docker.io/ui3o/dns-gateway:latest
	podman cp dns-gateway local-dns-gateway:/etc/dns-gateway
	podman cp src/dns-gateway local-dns-gateway:/opt/dns-gateway/dns-gateway
	podman start -ia local-dns-gateway

.PHONY: build setup-github-workspace run

print_cert:
	keytool -v -list -keystore certs/cacerts/keystore.jks -storepass changeit

setup-github-workspace:
	sudo apt-get update && sudo apt-get install -y podman golang openjdk-21-jre
	sudo mount --make-rshared /
	sudo ln -sf $(shell pwd)/dns-gateway /etc/dns-gateway

build:
	podman build -t dns-gateway:latest .

run:
	podman run -it localhost/dns-gateway:latest
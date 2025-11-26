.PHONY: build

setup-github-workspace:
	sudo apt-get update && sudo apt-get install -y podman golang
	sudo mount --make-rshared /

build:
	podman build -t dns-gateway:latest .

run:
	podman run -it localhost/dns-gateway:latest
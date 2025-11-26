print_cert:
	openssl x509 -in ca.crt -text -noout


gen_cert:
	rm -f *.key *.csr *.srl *.crt *.pem
	@echo Generate CA private key
	openssl genrsa -out ca.key 2048
	@echo Generate CA certificate
	openssl req -x509 -new -nodes -key ca.key -sha256 -days 3650 -out ca.crt -subj "/CN=CodeboxCA"
	@echo Generate server private key
	openssl genrsa -out server.key 2048
	@echo Generate server CSR Certificate Signing Request
	openssl req -new -key server.key -out server.csr -config san.cnf
	@echo Sign server certificate with CA
	openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
    -out server.crt -days 365 -sha256 -extensions req_ext -extfile san.cnf
	@echo Convert ca.crt to PEM format
	openssl x509 -in ca.crt -out ca.pem -outform PEM

install_cert:
	rm -f /etc/pki/ca-trust/source/anchors/ca.pem
	update-ca-trust
	cp ca.pem /etc/pki/ca-trust/source/anchors/
	update-ca-trust
	@echo export REQUESTS_CA_BUNDLE=/etc/pki/ca-trust/source/anchors/ca.pem
	@echo export CURL_CA_BUNDLE=/etc/pki/ca-trust/source/anchors/ca.pem
	@echo export GOPROXY=https://pkg.go.dev

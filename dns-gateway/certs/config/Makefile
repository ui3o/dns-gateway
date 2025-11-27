print_cert:
	cd .. && openssl x509 -in cacerts/ca.crt -text -noout

../ca/ca.crt:
	cd .. && rm -f ca/* cacerts/*
	@echo Generate CA private key
	cd .. && openssl genrsa -out ca/ca.key 2048
	@echo Generate CA certificate
	cd .. && openssl req -x509 -new -nodes -key ca/ca.key -sha256 -days 3650 -out ca/ca.crt -subj "/CN=DNSGatewayCA"
	@echo Copy ca/ca.crt to cacerts
	cd .. && cp ca/ca.crt cacerts/ca.crt

gen_ca_cert: ../ca/ca.crt

gen_server_cert: gen_ca_cert
	cd .. && rm -f server/*
	@echo Generate server/server private key
	cd .. && openssl genrsa -out server/server.key 2048
	@echo Generate server/server CSR Certificate Signing Request
	cd .. && openssl req -new -key server/server.key -out server/server.csr -config config/san.cnf
	@echo Sign server/server certificate with CA
	cd .. && openssl x509 -req -in server/server.csr -CA ca/ca.crt -CAkey ca/ca.key -CAcreateserial \
    -out server/server.crt -days 365 -sha256 -extensions req_ext -extfile config/san.cnf

install_cert:
	@echo export REQUESTS_CA_BUNDLE=/etc/pki/ca-trust/source/anchors/ca.pem
	@echo export CURL_CA_BUNDLE=/etc/pki/ca-trust/source/anchors/ca.pem
	@echo export GOPROXY=https://pkg.go.dev

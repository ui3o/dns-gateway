package main

import (
	"fmt"
	"log"
	"os"
	"regexp"
	"strings"
	"time"

	"crypto/x509"
	"encoding/pem"

	"github.com/pavlo-v-chernykh/keystore-go/v4"
)

func importCAIntoJKS(caCertPath, jksPath, alias, password string) error {
	// Read CA certificate
	certPEM, err := os.ReadFile(caCertPath)
	if err != nil {
		return fmt.Errorf("failed to read CA certificate: %w", err)
	}

	// Parse PEM certificate
	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return fmt.Errorf("failed to decode PEM block containing certificate")
	}

	// Create or load keystore
	ks := keystore.New()
	// Create trusted certificate entry
	trustedCert := keystore.TrustedCertificateEntry{
		CreationTime: time.Now(),
		Certificate: keystore.Certificate{
			Type:    "X.509",
			Content: block.Bytes,
		},
	}

	// Add certificate to keystore
	err = ks.SetTrustedCertificateEntry(alias, trustedCert)
	if err != nil {
		return fmt.Errorf("failed to set trusted certificate entry: %w", err)
	}

	// Save keystore to file
	file, err := os.Create(jksPath)
	if err != nil {
		return fmt.Errorf("failed to create JKS file: %w", err)
	}
	defer file.Close()

	err = ks.Store(file, []byte(password))
	if err != nil {
		return fmt.Errorf("failed to store keystore: %w", err)
	}

	log.Printf("Successfully imported CA certificate into JKS: %s", jksPath)
	return nil
}

func readDNAndAltNames(certPath string) (dn string, altNames map[string]bool, err error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return "", nil, fmt.Errorf("failed to read CA certificate: %w", err)
	}

	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return "", nil, fmt.Errorf("failed to decode PEM block containing certificate")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", nil, fmt.Errorf("failed to parse certificate: %w", err)
	}
	compiled := regexp.MustCompile("(cn *= *|o *= *|CN *= *|O *= *)")

	dn = strings.Trim(compiled.ReplaceAllString(cert.Subject.String(), ""), " ")
	altNames = make(map[string]bool)
	// altNames = append(cert.DNSNames, cert.EmailAddresses...)
	for _, dns := range cert.DNSNames {
		altNames[dns] = true
	}
	for _, ip := range cert.IPAddresses {
		altNames[ip.String()] = true
	}

	return dn, altNames, nil
}

func readDNAndAltNamesFromSANConf(sanConfPath string) (dn string, altNames map[string]bool, err error) {
	content, err := os.ReadFile(sanConfPath)
	if err != nil {
		return "", nil, fmt.Errorf("failed to read SAN config file: %w", err)
	}
	compiled := regexp.MustCompile("(cn *= *|o *= *|CN *= *|O *= *)")

	altNames = make(map[string]bool)
	lines := strings.Split(string(content), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "DNS.") || strings.HasPrefix(line, "IP.") || strings.HasPrefix(line, "email.") {
			parts := strings.Split(line, "=")
			if len(parts) == 2 {
				altNames[strings.TrimSpace(parts[1])] = true
			}
		}
		if compiled.MatchString(line) {
			dn = strings.Trim(compiled.ReplaceAllString(line, ""), " ")
		}
	}

	return dn, altNames, nil
}

func compareDNAndAltNames(certPath string, sanConfPath string) (generateNeed bool, err error) {
	crtDn, crtAltNames, crtErr := readDNAndAltNames(certPath)
	if crtErr != nil {
		return false, fmt.Errorf("reading certificate: %w", crtErr)
	}

	sanDn, sanAltNames, sanErr := readDNAndAltNamesFromSANConf(sanConfPath)
	if sanErr != nil {
		return false, fmt.Errorf("reading san.cnf: %w", sanErr)
	}
	if crtDn != sanDn {
		logger("INI", "crt dn '", crtDn, "' not match san.cnf dn '", sanDn, "'")
		return true, nil
	}
	for name := range sanAltNames {
		if _, exists := crtAltNames[name]; !exists {
			logger("INI", "alt name '", name, "' from san.cnf not found in certificate")
			return true, nil
		}
	}
	for name := range crtAltNames {
		if _, exists := sanAltNames[name]; !exists {
			logger("INI", "alt name '", name, "' from certificate not found in san.cnf")
			return true, nil
		}
	}
	return false, nil
}

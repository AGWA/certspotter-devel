// Copyright (C) 2026 Opsmate, Inc.
//
// This Source Code Form is subject to the terms of the Mozilla
// Public License, v. 2.0. If a copy of the MPL was not distributed
// with this file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// This software is distributed WITHOUT A WARRANTY OF ANY KIND.
// See the Mozilla Public License for details.

package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"software.sslmate.com/src/certspotter"
)

// Test certificate (self-signed, expires in the distant future)
const testCertPEM = `-----BEGIN CERTIFICATE-----
MIIDFzCCAf+gAwIBAgIUbiTpJponQlDPn9Kg/J+WpieykXowDQYJKoZIhvcNAQEL
BQAwGzEZMBcGA1UEAwwQdGVzdC5leGFtcGxlLmNvbTAeFw0yNjAxMDcyMzM3MzRa
Fw0yNzAxMDcyMzM3MzRaMBsxGTAXBgNVBAMMEHRlc3QuZXhhbXBsZS5jb20wggEi
MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCksUh4ffCRzZVqcBHhQulrG6ZC
jQQSJHMEDlisTsVZufZe7ofaYnns7aU5wL8Lo3kZwj1JKnvlrhFKm6kk0JJSt96w
Cg4tTk2k+7kqpCfTWqsJU5DPI2kpkrhktBSlvptLj5QR2A6RJxRs12FzhUXbZXc9
lCQiV0l431C4I1136Ssg/VuE+wsM4Z0cBUGIGjTAG1iqRZKizvDL68k+Q5PgAFIY
9BLxehQj6jjSRJ0Nh/NNSBavJDB76chUKXYrmbwum/ZOzs53CfjQ1ggojItUc2UA
a7mQcJZTaxRTB0Scpq+n5po1XMLV6464AHrkCWgUSb+MWu+7QYbKu+E0CjwDAgMB
AAGjUzBRMB0GA1UdDgQWBBQG+zaAUNwtb0BFycn6OphAdcggYTAfBgNVHSMEGDAW
gBQG+zaAUNwtb0BFycn6OphAdcggYTAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3
DQEBCwUAA4IBAQArg4s4SrgIfEF+p61zypZI17YqMUSW5ot91YlRpgmuBl8Uts5L
J583XfD4ClZ4RyteBlHIPBfwEBSnpcYVVDlr99TIZ4Fie+eworsWFRBsLZm24JTK
Gd290tDOxOpj37fIVMmmXYsHjw7jLCYxA3Rnyg5HJOjlORhuNxp6gLyROhSJyqLz
Dq7qJyIh8qyG+EPfVN2V39+ENe/GJmiGvw0vDaaFr+Jf5CcO2an/YIacCNNAjH73
nsbn2uv4uRDD5LzbBmME+nZij/GNuC/OM5HB0AINe1UCb/fJ524shYSKaAKKRb3H
wpuHBNJkxIiDMVlLT0NX6w/zgepAa2cnTy9P
-----END CERTIFICATE-----`

func TestParseCertificate(t *testing.T) {
	// Test PEM parsing
	certDER, err := parseCertificate([]byte(testCertPEM))
	if err != nil {
		t.Fatalf("parseCertificate failed: %v", err)
	}
	if len(certDER) == 0 {
		t.Fatal("parseCertificate returned empty DER")
	}

	// Test that we can parse the cert with certspotter library
	_, err = certspotter.MakeCertInfoFromRawCert(certDER)
	if err != nil {
		t.Fatalf("MakeCertInfoFromRawCert failed: %v", err)
	}
}

func TestComputeTBSHash(t *testing.T) {
	certDER, err := parseCertificate([]byte(testCertPEM))
	if err != nil {
		t.Fatalf("parseCertificate failed: %v", err)
	}

	tbsHash, err := computeTBSHash(certDER)
	if err != nil {
		t.Fatalf("computeTBSHash failed: %v", err)
	}

	// Verify hash is not empty
	zeroHash := [32]byte{}
	if bytes.Equal(tbsHash[:], zeroHash[:]) {
		t.Fatal("computeTBSHash returned zero hash")
	}

	// Verify consistency - computing again should give same result
	tbsHash2, err := computeTBSHash(certDER)
	if err != nil {
		t.Fatalf("computeTBSHash second call failed: %v", err)
	}
	if !bytes.Equal(tbsHash[:], tbsHash2[:]) {
		t.Fatal("computeTBSHash returned different hash on second call")
	}

	// Verify we compute the same hash as process.go does
	certInfo, err := certspotter.MakeCertInfoFromRawCert(certDER)
	if err != nil {
		t.Fatalf("MakeCertInfoFromRawCert failed: %v", err)
	}
	expectedHash := sha256.Sum256(certInfo.TBS.Raw)
	if !bytes.Equal(tbsHash[:], expectedHash[:]) {
		t.Fatalf("TBS hash mismatch: got %x, expected %x", tbsHash, expectedHash)
	}
}

func TestCreateNotifiedMarker(t *testing.T) {
	stateDir := t.TempDir()

	certDER, err := parseCertificate([]byte(testCertPEM))
	if err != nil {
		t.Fatalf("parseCertificate failed: %v", err)
	}

	tbsHash, err := computeTBSHash(certDER)
	if err != nil {
		t.Fatalf("computeTBSHash failed: %v", err)
	}

	// First call should create the marker
	notifiedPath, err := createNotifiedMarker(stateDir, tbsHash)
	if err != nil {
		t.Fatalf("createNotifiedMarker failed: %v", err)
	}

	// Verify marker file exists
	if !fileExists(notifiedPath) {
		t.Fatalf("marker file does not exist: %s", notifiedPath)
	}

	// Verify path structure is correct
	tbsHex := hex.EncodeToString(tbsHash[:])
	expectedPath := filepath.Join(stateDir, "certs", tbsHex[0:2], "."+tbsHex+".notified")
	if notifiedPath != expectedPath {
		t.Fatalf("unexpected marker path: got %s, expected %s", notifiedPath, expectedPath)
	}

	// Second call should succeed (idempotency)
	notifiedPath2, err := createNotifiedMarker(stateDir, tbsHash)
	if err != nil {
		t.Fatalf("createNotifiedMarker second call failed: %v", err)
	}
	if notifiedPath != notifiedPath2 {
		t.Fatalf("second call returned different path: got %s, expected %s", notifiedPath2, notifiedPath)
	}
}

func TestReadCertFile(t *testing.T) {
	// Test reading from a file
	tmpDir := t.TempDir()
	certPath := filepath.Join(tmpDir, "cert.pem")
	if err := os.WriteFile(certPath, []byte(testCertPEM), 0644); err != nil {
		t.Fatalf("failed to write test cert: %v", err)
	}

	certBytes, err := readCertFile(certPath)
	if err != nil {
		t.Fatalf("readCertFile failed: %v", err)
	}
	if !bytes.Equal(certBytes, []byte(testCertPEM)) {
		t.Fatal("readCertFile returned different content")
	}
}

func TestFileExists(t *testing.T) {
	tmpDir := t.TempDir()

	// Test with non-existent file
	if fileExists(filepath.Join(tmpDir, "nonexistent")) {
		t.Fatal("fileExists returned true for non-existent file")
	}

	// Test with existing file
	existingFile := filepath.Join(tmpDir, "existing")
	if err := os.WriteFile(existingFile, []byte("test"), 0644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}
	if !fileExists(existingFile) {
		t.Fatal("fileExists returned false for existing file")
	}
}

func TestEndToEnd(t *testing.T) {
	stateDir := t.TempDir()

	certDER, err := parseCertificate([]byte(testCertPEM))
	if err != nil {
		t.Fatalf("parseCertificate failed: %v", err)
	}

	tbsHash, err := computeTBSHash(certDER)
	if err != nil {
		t.Fatalf("computeTBSHash failed: %v", err)
	}

	notifiedPath, err := createNotifiedMarker(stateDir, tbsHash)
	if err != nil {
		t.Fatalf("createNotifiedMarker failed: %v", err)
	}

	// Verify the marker file structure matches what monitor/fsstate.go expects
	tbsHex := hex.EncodeToString(tbsHash[:])
	expectedDir := filepath.Join(stateDir, "certs", tbsHex[0:2])
	expectedFile := filepath.Join(expectedDir, "."+tbsHex+".notified")

	if notifiedPath != expectedFile {
		t.Fatalf("unexpected marker path: got %s, expected %s", notifiedPath, expectedFile)
	}

	if !fileExists(expectedFile) {
		t.Fatalf("marker file does not exist: %s", expectedFile)
	}

	// Verify file is empty (as expected by certspotter)
	stat, err := os.Stat(expectedFile)
	if err != nil {
		t.Fatalf("failed to stat marker file: %v", err)
	}
	if stat.Size() != 0 {
		t.Fatalf("marker file should be empty, but has size %d", stat.Size())
	}
}

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
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime/debug"
	"strconv"
	"strings"

	"software.sslmate.com/src/certspotter"
)

var programName = os.Args[0]
var Version = "unknown"
var Source = "unknown"

func certspotterVersion() (string, string) {
	if buildinfo, ok := debug.ReadBuildInfo(); ok && strings.HasPrefix(buildinfo.Main.Version, "v") {
		return strings.TrimPrefix(buildinfo.Main.Version, "v"), buildinfo.Main.Path
	} else {
		return Version, Source
	}
}

func homedir() string {
	homedir, err := os.UserHomeDir()
	if err != nil {
		panic(fmt.Errorf("unable to determine home directory: %w", err))
	}
	return homedir
}

func startedBySupervisor() bool {
	return os.Getenv("SYSTEMD_EXEC_PID") == strconv.Itoa(os.Getpid())
}

func defaultStateDir() string {
	if envVar := os.Getenv("CERTSPOTTER_STATE_DIR"); envVar != "" {
		return envVar
	} else if envVar := os.Getenv("STATE_DIRECTORY"); envVar != "" && startedBySupervisor() {
		return envVar
	} else {
		return filepath.Join(homedir(), ".certspotter")
	}
}

func fileExists(filename string) bool {
	_, err := os.Lstat(filename)
	return err == nil
}

func readCertFile(path string) ([]byte, error) {
	var reader io.Reader
	if path == "-" {
		reader = os.Stdin
	} else {
		file, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		defer file.Close()
		reader = file
	}
	return io.ReadAll(reader)
}

func parseCertificate(certBytes []byte) ([]byte, error) {
	// Try to decode as PEM first
	block, _ := pem.Decode(certBytes)
	if block != nil {
		if block.Type == "CERTIFICATE" {
			return block.Bytes, nil
		}
		return nil, fmt.Errorf("PEM block type is %q, expected CERTIFICATE", block.Type)
	}
	// If not PEM, assume it's DER
	return certBytes, nil
}

func computeTBSHash(certDER []byte) ([32]byte, error) {
	certInfo, err := certspotter.MakeCertInfoFromRawCert(certDER)
	if err != nil {
		return [32]byte{}, fmt.Errorf("error parsing certificate: %w", err)
	}
	return sha256.Sum256(certInfo.TBS.Raw), nil
}

func createNotifiedMarker(stateDir string, tbsHash [32]byte) (string, error) {
	tbsHex := hex.EncodeToString(tbsHash[:])
	if len(tbsHex) < 2 {
		return "", fmt.Errorf("TBS hash hex is too short: %d characters", len(tbsHex))
	}

	tbsDir := filepath.Join(stateDir, "certs", tbsHex[0:2])
	notifiedPath := filepath.Join(tbsDir, "."+tbsHex+".notified")

	// Check if already notified
	if fileExists(notifiedPath) {
		return notifiedPath, nil
	}

	// Create directory if needed
	if err := os.MkdirAll(tbsDir, 0777); err != nil {
		return "", fmt.Errorf("error creating directory: %w", err)
	}

	// Create marker file
	if err := os.WriteFile(notifiedPath, nil, 0666); err != nil {
		return "", fmt.Errorf("error creating marker file: %w", err)
	}

	return notifiedPath, nil
}

func main() {
	version, source := certspotterVersion()

	var flags struct {
		cert     string
		stateDir string
		version  bool
	}

	flag.StringVar(&flags.cert, "cert", "", "Path to a PEM or DER encoded certificate (use - to read from stdin)")
	flag.StringVar(&flags.stateDir, "state_dir", defaultStateDir(), "State directory used by certspotter")
	flag.BoolVar(&flags.version, "version", false, "Print version and exit")
	flag.Parse()

	if flags.version {
		fmt.Fprintf(os.Stdout, "certspotter-authorize version %s (%s)\n", version, source)
		os.Exit(0)
	}

	if flags.cert == "" {
		fmt.Fprintf(os.Stderr, "Usage: %s -cert PATH [-state_dir PATH]\n\n", programName)
		fmt.Fprintf(os.Stderr, "Compute TBSCertificate SHA-256 and create a .notified marker to suppress\n")
		fmt.Fprintf(os.Stderr, "future certspotter notifications for certificates with the same TBSCertificate.\n\n")
		fmt.Fprintf(os.Stderr, "Options:\n")
		flag.PrintDefaults()
		os.Exit(2)
	}

	certBytes, err := readCertFile(flags.cert)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: error reading certificate: %s\n", programName, err)
		os.Exit(1)
	}

	certDER, err := parseCertificate(certBytes)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: %s\n", programName, err)
		os.Exit(1)
	}

	tbsHash, err := computeTBSHash(certDER)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: %s\n", programName, err)
		os.Exit(1)
	}

	_, err = createNotifiedMarker(flags.stateDir, tbsHash)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: %s\n", programName, err)
		os.Exit(1)
	}

	// Success - no output
	os.Exit(0)
}

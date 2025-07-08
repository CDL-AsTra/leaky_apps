package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/defaults"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
)

type DetectedSecret struct {
	Detector    string `json:"detector"`
	Secret      string `json:"secret"`
	Verified    bool   `json:"verified"`
	Reason      string `json:"reason"`
	Llama3_done bool   `json:"llama3_done"`
}

func read_secret_file(filename string) DetectedSecret {
	file, err := os.Open(filename)
	if err != nil {
		return DetectedSecret{}
	}
	defer file.Close()

	secret := DetectedSecret{}
	decoder := json.NewDecoder(file)
	err = decoder.Decode(&secret)
	if err != nil {
		return DetectedSecret{}
	}

	return secret
}

func (e *Engine) ScanVerify(ctx context.Context, filename string) (sources.JobProgressRef, error) {
	fmt.Println("Scanning and verifying secrets")
	secret := read_secret_file(filename)

	detectors := defaults.DefaultDetectors()
	//TODO: find the right detctor
	fmt.Println("verifying secret: ", secret.Secret)

	// Use the config as needed
	for _, c := range detectors {
		// Do something with c
		if fmt.Sprintf("%d", c.Type().Number()) == secret.Detector {
			fmt.Println("Found detector: ", c.Type())
			verified := c.Verify(context.Background(), secret.Secret)
			secret.Verified = verified
			fmt.Println("Secret verified: ", verified)
			secret.Reason = "trufflehog"

			file, err := os.Create(filename)
			if err != nil {
				return sources.JobProgressRef{}, err
			}
			defer file.Close()

			encoder := json.NewEncoder(file)
			err = encoder.Encode(&secret)
			if err != nil {
				return sources.JobProgressRef{}, err
			}

		}
	}
	return sources.JobProgressRef{}, nil
}

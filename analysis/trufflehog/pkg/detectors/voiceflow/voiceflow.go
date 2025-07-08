package voiceflow

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct {
	client *http.Client
}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	defaultClient = common.SaneHttpClient()
	// Reference: https://developer.voiceflow.com/reference/project#dialog-manager-api-keys
	//
	// TODO: This includes Workspace and Legacy Workspace API keys; I haven't validated whether these actually work.
	// https://github.com/voiceflow/general-runtime/blob/master/tests/runtime/lib/DataAPI/utils.unit.ts
	keyPat = regexp.MustCompile(`\b(VF\.(?:(?:DM|WS)\.)?[a-fA-F0-9]{24}\.[a-zA-Z0-9]{16})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"vf", "dm"}
}

// FromData will find and optionally verify Voiceflow secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)
	matches := keyPat.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {
		if len(match) != 2 {
			continue
		}
		resMatch := strings.TrimSpace(match[1])

		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_Voiceflow,
			Raw:          []byte(resMatch),
		}

		if verify {
			client := s.client
			if client == nil {
				client = defaultClient
			}
			verified, err := verifyMatch(ctx, client, resMatch)

			if err != nil {
				continue
			}
			s1.Verified = verified

		}

		results = append(results, s1)
	}

	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Voiceflow
}

func (s Scanner) Verify(ctx context.Context, secret string) bool {
	verified, _ := verifyMatch(ctx, defaultClient, secret)
	return verified
}

func verifyMatch(ctx context.Context, client *http.Client, resMatch string) (bool, error) {
	// Fetch the state for a random user.
	payload := []byte(`{"question": "why is the sky blue?"}`)
	req, err := http.NewRequestWithContext(ctx, "POST", "https://general-runtime.voiceflow.com/knowledge-base/query", bytes.NewBuffer(payload))
	if err != nil {
		return false, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", resMatch)
	req.Header.Set("Content-Type", "application/json")

	res, err := client.Do(req)
	if err == nil {
		if res.StatusCode == http.StatusOK {
			return true, nil
		} else if res.StatusCode == http.StatusUnauthorized {
			// The secret is determinately not verified (nothing to do)
		} else {
			var buf bytes.Buffer
			var bodyString string
			_, err = io.Copy(&buf, res.Body)
			if err == nil {
				bodyString = buf.String()
			}
			verificationErr := fmt.Errorf("unexpected HTTP response [status=%d, body=%s]", res.StatusCode, bodyString)
			return false, verificationErr

		}
		_ = res.Body.Close()
	}
	return false, nil
}

func (s Scanner) Description() string {

	return "Voiceflow is an AI service designed to transact with customers. API keys may be used to access customer data."
}

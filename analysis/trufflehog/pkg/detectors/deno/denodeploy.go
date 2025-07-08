package denodeploy

import (
	"context"
	"fmt"
	"net/http"

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
	tokenPat      = regexp.MustCompile(`\b(dd[pw]_[a-zA-Z0-9]{36})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"ddp_", "ddw_"}
}

type userResponse struct {
	Login string `json:"login"`
}

// FromData will find and optionally verify DenoDeploy secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	tokenMatches := tokenPat.FindAllStringSubmatch(dataStr, -1)

	for _, tokenMatch := range tokenMatches {
		token := tokenMatch[1]

		s1 := detectors.Result{
			DetectorType: s.Type(),
			Raw:          []byte(token),
		}

		if verify {

			client := s.client
			if client == nil {
				client = defaultClient
			}
			verified, err := verifyMatch(ctx, client, token)
			if err != nil {
				continue
			}
			s1.Verified = verified
		}

		results = append(results, s1)
	}

	return results, nil
}
func verifyMatch(ctx context.Context, client *http.Client, token string) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", "https://api.deno.com/user", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	if err != nil {
		return false, err
	}

	res, err := client.Do(req)
	if err == nil {
		defer res.Body.Close()
		if res.StatusCode == 200 {

			return true, nil
		} else if res.StatusCode == 401 {
			// The secret is determinately not verified (nothing to do)
		} else {
			err = fmt.Errorf("unexpected HTTP response status %d", res.StatusCode)
		}
	}

	return false, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_DenoDeploy
}

func (s Scanner) Description() string {
	return "DenoDeploy is a cloud service for deploying JavaScript and TypeScript applications. DenoDeploy tokens can be used to access and manage these deployments."
}

func (s Scanner) Verify(ctx context.Context, secret string) bool {
	verified, _ := verifyMatch(ctx, defaultClient, secret)
	return verified
}

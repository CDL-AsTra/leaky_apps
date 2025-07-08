package asanapersonalaccesstoken

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct{}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	client = common.SaneHttpClient()

	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"asana"}) + `\b([0-9]{1,}\/[0-9]{16,}:[A-Za-z0-9]{32,})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"asana"}
}

// FromData will find and optionally verify AsanaPersonalAccessToken secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := keyPat.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {
		if len(match) != 2 {
			continue
		}
		resMatch := strings.TrimSpace(match[1])

		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_AsanaPersonalAccessToken,
			Raw:          []byte(resMatch),
		}

		if verify {
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

func verifyMatch(ctx context.Context, client *http.Client, secret string) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", "https://app.asana.com/api/1.0/users/me", nil)
	if err != nil {
		return false, err
	}
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", secret))
	res, err := client.Do(req)
	if err == nil {
		defer res.Body.Close()
		if res.StatusCode >= 200 && res.StatusCode < 300 {
			return true, nil
		}
	}
	return false, nil

}

func (s Scanner) Verify(ctx context.Context, secret string) bool {
	verified, _ := verifyMatch(ctx, client, secret)
	return verified
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_AsanaPersonalAccessToken
}

func (s Scanner) Description() string {
	return "Asana is a web and mobile application designed to help teams organize, track, and manage their work. Asana Personal Access Tokens can be used to access and modify data within Asana."
}

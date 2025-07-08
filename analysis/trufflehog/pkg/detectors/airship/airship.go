package airship

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

	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives.
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"airship"}) + `\b([0-9a-zA-Z]{91})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"airship"}
}

// FromData will find and optionally verify Airship secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := keyPat.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {
		if len(match) != 2 {
			continue
		}
		resMatch := strings.TrimSpace(match[1])

		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_Airship,
			Raw:          []byte(resMatch),
		}

		if verify {
			verified, err := verifyAirship(ctx, client, resMatch)
			if err != nil {
				continue
			}
			s1.Verified = verified
		}

		results = append(results, s1)
	}

	return results, nil
}

func verifyAirship(ctx context.Context, client *http.Client, secret string) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", "https://go.urbanairship.com/api/schedules", nil)
	if err != nil {
		return false, err
	}
	req.Header.Add("Accept", "application/vnd.urbanairship+json; version=3")
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
	isVerified, _ := verifyAirship(ctx, client, secret)
	return isVerified
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Airship
}

func (s Scanner) Description() string {
	return "Airship is a customer engagement platform that provides tools for mobile app messaging, in-app messaging, and web notifications. Airship API keys can be used to access and manage these messaging services."
}

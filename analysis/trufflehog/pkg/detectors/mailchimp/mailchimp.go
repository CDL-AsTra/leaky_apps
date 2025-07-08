package mailchimp

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
)

type Scanner struct{}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	client = common.SaneHttpClient()
	keyPat = regexp.MustCompile(`[0-9a-f]{32}-us[0-9]{1,2}`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"-us"}
}

// FromData will find and optionally verify Mailchimp secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	// pretty standard regex match
	matches := keyPat.FindAllString(dataStr, -1)

	for _, match := range matches {

		result := detectors.Result{
			DetectorType: detectorspb.DetectorType_Mailchimp,
			Raw:          []byte(match),
		}
		result.ExtraData = map[string]string{
			"rotation_guide": "https://howtorotate.com/docs/tutorials/mailchimp/",
		}

		if verify {
			verified, err := verifyMatch(ctx, client, match)
			if err != nil {
				continue
			}
			result.Verified = verified

		}

		results = append(results, result)
	}

	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Mailchimp
}

func (s Scanner) Verify(ctx context.Context, secret string) bool {
	verified, _ := verifyMatch(ctx, client, secret)
	return verified
}

func verifyMatch(ctx context.Context, client *http.Client, resMatch string) (bool, error) {

	datacenter := strings.Split(resMatch, "-")[1]

	// https://mailchimp.com/developer/guides/marketing-api-conventions/
	req, err := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("https://%s.api.mailchimp.com/3.0/", datacenter), nil)
	if err != nil {
		return false, err
	}
	req.SetBasicAuth("anystring", resMatch)
	req.Header.Add("accept", "application/json")
	res, err := client.Do(req)
	if err == nil {
		defer res.Body.Close()
		if res.StatusCode >= 200 && res.StatusCode < 300 {
			return true, nil
		}
	}

	return false, nil
}

func (s Scanner) Description() string {

	return "Mailchimp is a marketing automation platform and email marketing service. Mailchimp API keys can be used to access and manage email campaigns, audience data, and other marketing resources."
}

package axonaut

import (
	"context"
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
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"axonaut"}) + `\b([a-z0-9]{32})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"axonaut"}
}

// FromData will find and optionally verify Axonaut secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := keyPat.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {
		if len(match) != 2 {
			continue
		}
		resMatch := strings.TrimSpace(match[1])

		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_Axonaut,
			Raw:          []byte(resMatch),
		}

		if verify {
		}

		results = append(results, s1)
	}

	return results, nil
}

func verifyMatch(ctx context.Context, client *http.Client, secret string) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", "https://axonaut.com/api/v2/companies?type=all&sort=id", nil)
	if err != nil {
		return false, err
	}
	req.Header.Add("userApiKey", secret)
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
	return detectorspb.DetectorType_Axonaut
}

func (s Scanner) Description() string {
	return "Axonaut is a service that provides business management solutions including CRM, invoicing, and accounting. Axonaut API keys can be used to access and manage business data through their API."
}

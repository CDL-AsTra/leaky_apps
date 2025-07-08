package hypertrack

import (
	"context"
	"net/http"
	"strings"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct {
	detectors.DefaultMultiPartCredentialProvider
}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	client = common.SaneHttpClient()

	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives.'
	accPat = regexp.MustCompile(detectors.PrefixRegex([]string{"hypertrack"}) + `\b([0-9a-zA-Z\_\-]{27})\b`)
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"hypertrack"}) + `\b([0-9a-zA-Z\_\-]{54})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"hypertrack"}
}

// FromData will find and optionally verify Hypertrack secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	accMatches := accPat.FindAllStringSubmatch(dataStr, -1)
	matches := keyPat.FindAllStringSubmatch(dataStr, -1)

	for _, accMatch := range accMatches {

		if len(accMatch) != 2 {
			continue
		}
		resAccMatch := strings.TrimSpace(accMatch[1])

		for _, match := range matches {
			if len(match) != 2 {
				continue
			}
			resMatch := strings.TrimSpace(match[1])

			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_Hypertrack,
				Raw:          []byte(resMatch),
				RawV2:        []byte(resMatch + resAccMatch),
			}

			if verify {
				verified, err := verifyMatch(ctx, client, resMatch, resAccMatch)
				if err != nil {
					continue
				}
				s1.Verified = verified

			}

			results = append(results, s1)
		}
	}

	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Hypertrack
}

func (s Scanner) Verify(ctx context.Context, secret string) bool {
	parts := strings.Split(secret, ";-|")
	if len(parts) != 2 {
		return false
	}

	verified, _ := verifyMatch(ctx, client, parts[0], parts[1])
	return verified
}

func verifyMatch(ctx context.Context, client *http.Client, resMatch, resAccMatch string) (bool, error) {

	req, err := http.NewRequestWithContext(ctx, "GET", "https://v3.api.hypertrack.com/trips/", nil)
	if err != nil {
		return false, err
	}
	req.SetBasicAuth(resAccMatch, resMatch)
	req.Header.Add("Content-Type", "application/json")
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

	return "Hypertrack is a service that provides live location tracking for fleets and other mobile workforce management. Hypertrack keys can be used to access and manage these tracking services."
}

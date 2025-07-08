package amplitudeapikey

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

	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives.
	keyPat    = regexp.MustCompile(detectors.PrefixRegex([]string{"amplitude"}) + `\b([0-9a-f]{32})\b`)
	secretPat = regexp.MustCompile(detectors.PrefixRegex([]string{"amplitude"}) + `\b([0-9a-f]{32})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"amplitude"}
}

// FromData will find and optionally verify AmplitudeApiKey secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := keyPat.FindAllStringSubmatch(dataStr, -1)
	secretMatches := secretPat.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {
		if len(match) != 2 {
			continue
		}
		resMatch := strings.TrimSpace(match[1])

		for _, secretMatch := range secretMatches {
			if len(secretMatch) != 2 {
				continue
			}
			resSecretMatch := strings.TrimSpace(secretMatch[1])

			// regex for both key and secret are same so the set of strings could possibly be same as well
			if resMatch == resSecretMatch {
				continue
			}

			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_AmplitudeApiKey,
				Raw:          []byte(resMatch),
				RawV2:        []byte(resMatch + resSecretMatch),
			}

			if verify {
				verified, err := verifyMatch(ctx, client, resMatch, resSecretMatch)
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

func verifyMatch(ctx context.Context, client *http.Client, resMatch, resSecretMatch string) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", "https://amplitude.com/api/2/taxonomy/category", nil)
	if err != nil {
		return false, err
	}
	req.SetBasicAuth(resMatch, resSecretMatch)
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
	parts := strings.Split(secret, ";-|")
	if len(parts) != 2 {
		return false
	}

	verified, _ := verifyMatch(ctx, client, parts[0], parts[1])
	return verified
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_AmplitudeApiKey
}

func (s Scanner) Description() string {
	return "Amplitude is a product analytics service that helps companies track and analyze user behavior within web and mobile applications. Amplitude API keys can be used to access and modify this data."
}

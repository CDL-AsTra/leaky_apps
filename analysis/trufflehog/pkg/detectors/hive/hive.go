package hive

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
	idPat  = regexp.MustCompile(detectors.PrefixRegex([]string{"hive"}) + `\b([0-9A-Za-z]{17})\b`)
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"hive"}) + `\b([0-9a-z]{32})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"hive"}
}

// FromData will find and optionally verify Hive secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	idMatches := idPat.FindAllStringSubmatch(dataStr, -1)
	keyMatches := keyPat.FindAllStringSubmatch(dataStr, -1)

	for _, match := range idMatches {
		if len(match) != 2 {
			continue
		}

		idMatch := strings.TrimSpace(match[1])

		for _, match := range keyMatches {
			if len(match) != 2 {
				continue
			}
			keyMatch := strings.TrimSpace(match[1])

			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_Hive,
				Raw:          []byte(idMatch),
				RawV2:        []byte(idMatch + keyMatch),
			}

			if verify {
				verified, err := verifyMatch(ctx, client, idMatch, keyMatch)
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
	return detectorspb.DetectorType_Hive
}

func (s Scanner) Verify(ctx context.Context, secret string) bool {
	parts := strings.Split(secret, ";-|")
	if len(parts) != 2 {
		return false
	}

	verified, _ := verifyMatch(ctx, client, parts[0], parts[1])
	return verified
}
func verifyMatch(ctx context.Context, client *http.Client, idMatch, keyMatch string) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", "https://app.hive.com/api/v1/testcredentials?user_id="+idMatch+"&api_key="+keyMatch, nil)
	if err != nil {
		return false, err
	}
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

	return "Hive is a project management and collaboration tool. Hive API keys can be used to access and manage projects, tasks, and other data within a Hive workspace."
}

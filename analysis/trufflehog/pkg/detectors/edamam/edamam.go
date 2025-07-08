package edamam

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

type Scanner struct {
	detectors.DefaultMultiPartCredentialProvider
}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	client = common.SaneHttpClient()

	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives.
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"edamam"}) + `\b([0-9a-z]{32})\b`)
	idPat  = regexp.MustCompile(detectors.PrefixRegex([]string{"edamam"}) + `\b([0-9a-z]{8})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"edamam"}
}

// FromData will find and optionally verify Edamam secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := keyPat.FindAllStringSubmatch(dataStr, -1)
	idMatches := idPat.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {
		if len(match) != 2 {
			continue
		}
		resMatch := strings.TrimSpace(match[1])
		for _, idMatch := range idMatches {
			if len(match) != 2 {
				continue
			}
			resId := strings.TrimSpace(idMatch[1])
			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_Edamam,
				Raw:          []byte(resMatch),
				RawV2:        []byte(resMatch + resId),
			}

			if verify {
				verified, err := verifyMatch(ctx, client, resMatch, resId)
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
	return detectorspb.DetectorType_Edamam
}

func (s Scanner) Description() string {
	return "Edamam provides nutrition analysis and diet recommendations. Edamam API keys can be used to access and modify nutrition data and perform diet analysis."
}

func (s Scanner) Verify(ctx context.Context, secret string) bool {
	parts := strings.Split(secret, ";-|")
	if len(parts) != 2 {
		return false
	}

	verified, _ := verifyMatch(ctx, client, parts[0], parts[1])
	return verified
}
func verifyMatch(ctx context.Context, client *http.Client, resMatch, resId string) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("https://api.edamam.com/auto-complete?app_id=%s&app_key=%s&q=%s", resId, resMatch, ""), nil)
	if err != nil {
		return false, err
	}
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

package mapbox

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
	idPat  = regexp.MustCompile(`([a-zA-Z-0-9]{4,32})`)
	keyPat = regexp.MustCompile(`\b(sk\.[a-zA-Z-0-9\.]{80,240})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"mapbox"}
}

// FromData will find and optionally verify MapBox secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := keyPat.FindAllStringSubmatch(dataStr, -1)
	idMatches := idPat.FindAllStringSubmatch(dataStr, -1)
	for _, match := range matches {

		resMatch := strings.TrimSpace(match[1])
		for i, idMatch := range idMatches {
			if i == 11 {
				if len(idMatch) != 2 {
					continue
				}
				resId := strings.TrimSpace(idMatch[1])

				s1 := detectors.Result{
					DetectorType: detectorspb.DetectorType_MapBox,
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

	}

	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_MapBox
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
	req, err := http.NewRequestWithContext(ctx, "GET", "https://api.mapbox.com/tokens/v2/"+resId+"?access_token="+resMatch, nil)
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

	return "Mapbox provides location-based services and APIs. Mapbox access tokens can be used to interact with these services and modify data."
}

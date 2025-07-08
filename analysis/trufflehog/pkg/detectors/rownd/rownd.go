package rownd

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
	keyPat    = regexp.MustCompile(detectors.PrefixRegex([]string{"rownd"}) + `\b([a-z0-9]{8}\-[a-z0-9]{4}\-[a-z0-9]{4}\-[a-z0-9]{4}\-[a-z0-9]{12})\b`)
	secretPat = regexp.MustCompile(detectors.PrefixRegex([]string{"rownd"}) + `\b([a-z0-9]{48})\b`)
	idPat     = regexp.MustCompile(detectors.PrefixRegex([]string{"rownd"}) + `\b([0-9]{18})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"rownd"}
}

// FromData will find and optionally verify Rownd secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	idMatches := idPat.FindAllStringSubmatch(dataStr, -1)
	keyMatches := keyPat.FindAllStringSubmatch(dataStr, -1)
	secretMatches := secretPat.FindAllStringSubmatch(dataStr, -1)

	for _, idMatch := range idMatches {
		if len(idMatch) != 2 {
			continue
		}
		resId := strings.TrimSpace(idMatch[1])

		for _, match := range keyMatches {
			if len(match) != 2 {
				continue
			}
			keyMatch := strings.TrimSpace(match[1])

			for _, secret := range secretMatches {
				if len(secret) != 2 {
					continue
				}

				secretMatch := strings.TrimSpace(secret[1])

				s1 := detectors.Result{
					DetectorType: detectorspb.DetectorType_Rownd,
					Raw:          []byte(keyMatch),
					RawV2:        []byte(keyMatch + ";-|" + secretMatch + ";-|" + resId),
				}

				if verify {
					verified, err := verifyMatch(ctx, client, keyMatch, secretMatch, resId)
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
	return detectorspb.DetectorType_Rownd
}

func (s Scanner) Verify(ctx context.Context, secret string) bool {
	parts := strings.Split(secret, ";-|")
	if len(parts) != 3 {
		return false
	}

	verified, _ := verifyMatch(ctx, client, parts[0], parts[1], parts[2])
	return verified
}
func verifyMatch(ctx context.Context, client *http.Client, keyMatch, secretMatch, resId string) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", "https://api.rownd.io/applications/"+resId+"/users/data", nil)
	if err != nil {
		return false, err
	}
	req.Header.Add("x-rownd-app-key", keyMatch)
	req.Header.Add("x-rownd-app-secret", secretMatch)
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

	return "Rownd is a platform for user data management. Rownd credentials can be used to access and modify user data and application settings."
}

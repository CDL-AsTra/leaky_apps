package guru

import (
	"context"
	b64 "encoding/base64"
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
	unamePat = regexp.MustCompile(detectors.PrefixRegex([]string{"guru"}) + `\b([a-zA-Z0-9]{3,20}@[a-zA-Z0-9]{2,12}.[a-zA-Z0-9]{2,5})\b`)
	keyPat   = regexp.MustCompile(detectors.PrefixRegex([]string{"guru"}) + `\b([a-z0-9]{8}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{12})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"guru"}
}

// FromData will find and optionally verify Guru secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	unameMatches := unamePat.FindAllStringSubmatch(dataStr, -1)
	keyMatches := keyPat.FindAllStringSubmatch(dataStr, -1)

	for _, match := range unameMatches {
		if len(match) != 2 {
			continue
		}

		unameMatch := strings.TrimSpace(match[1])

		for _, secret := range keyMatches {
			if len(secret) != 2 {
				continue
			}

			keyMatch := strings.TrimSpace(secret[1])

			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_Guru,
				Raw:          []byte(unameMatch),
				RawV2:        []byte(unameMatch + keyMatch),
			}

			if verify {
				verified, err := verifyMatch(ctx, client, unameMatch, keyMatch)
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
	return detectorspb.DetectorType_Guru
}

func (s Scanner) Verify(ctx context.Context, secret string) bool {
	parts := strings.Split(secret, ";-|")
	if len(parts) != 2 {
		return false
	}

	verified, _ := verifyMatch(ctx, client, parts[0], parts[1])
	return verified
}

func verifyMatch(ctx context.Context, client *http.Client, unameMatch, keyMatch string) (bool, error) {

	data := fmt.Sprintf("%s:%s", unameMatch, keyMatch)
	encoded := b64.StdEncoding.EncodeToString([]byte(data))

	req, err := http.NewRequestWithContext(ctx, "GET", "https://api.getguru.com/api/v1/teams/teamId/stats", nil)
	if err != nil {
		return false, err
	}
	req.Header.Add("Authorization", fmt.Sprintf("Basic %s", encoded))
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

	return "Guru is a knowledge management solution. Guru credentials can be used to access and manage knowledge within an organization."
}

package mattermostpersonaltoken

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
	keyPat    = regexp.MustCompile(detectors.PrefixRegex([]string{"mattermost"}) + `\b([a-z0-9]{26})\b`)
	serverPat = regexp.MustCompile(detectors.PrefixRegex([]string{"mattermost"}) + `\b([A-Za-z0-9-_]{1,}.cloud.mattermost.com)\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"mattermost"}
}

// FromData will find and optionally verify MattermostPersonalToken secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := keyPat.FindAllStringSubmatch(dataStr, -1)
	serverMatches := serverPat.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {
		if len(match) != 2 {
			continue
		}
		resMatch := strings.TrimSpace(match[1])

		for _, serverMatch := range serverMatches {
			if len(serverMatch) != 2 {
				continue
			}
			serverRes := strings.TrimSpace(serverMatch[1])

			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_MattermostPersonalToken,
				Raw:          []byte(resMatch),
				RawV2:        []byte(resMatch + serverRes),
			}

			if verify {
				verified, err := verifyMatch(ctx, client, resMatch, serverRes)
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
	return detectorspb.DetectorType_MattermostPersonalToken
}

func (s Scanner) Verify(ctx context.Context, secret string) bool {
	parts := strings.Split(secret, ";-|")
	if len(parts) != 2 {
		return false
	}

	verified, _ := verifyMatch(ctx, client, parts[0], parts[1])
	return verified
}
func verifyMatch(ctx context.Context, client *http.Client, resMatch, serverRes string) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", "https://"+serverRes+"/api/v4/users/stats", nil)
	if err != nil {
		return false, err
	}
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", resMatch))
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

	return "Mattermost is an open-source, self-hostable online chat service with file sharing, search, and integrations. Mattermost Personal Tokens can be used to authenticate API requests to a Mattermost server."
}

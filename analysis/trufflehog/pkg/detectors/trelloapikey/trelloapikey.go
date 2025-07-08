package trelloapikey

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
	client   = common.SaneHttpClient()
	tokenPat = regexp.MustCompile(`\b([a-zA-Z-0-9]{64})\b`)
	keyPat   = regexp.MustCompile(detectors.PrefixRegex([]string{"trello"}) + `\b([a-zA-Z-0-9]{32})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"trello"}
}

// FromData will find and optionally verify TrelloApiKey secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := keyPat.FindAllStringSubmatch(dataStr, -1)
	tokenMatches := tokenPat.FindAllStringSubmatch(dataStr, -1)

	for i, match := range matches {
		if i == 0 {
			resMatch := strings.TrimSpace(match[1])
			for _, tokenMatch := range tokenMatches {
				if len(tokenMatch) != 2 {
					continue
				}

				token := strings.TrimSpace(tokenMatch[1])

				s1 := detectors.Result{
					DetectorType: detectorspb.DetectorType_TrelloApiKey,
					Redacted:     resMatch,
					Raw:          []byte(resMatch),
					RawV2:        []byte(resMatch + token),
				}

				if verify {
					verified, err := verifyMatch(ctx, client, resMatch, token)
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
	return detectorspb.DetectorType_TrelloApiKey
}

func (s Scanner) Verify(ctx context.Context, secret string) bool {
	parts := strings.Split(secret, ";-|")
	if len(parts) != 2 {
		return false
	}

	verified, _ := verifyMatch(ctx, client, parts[0], parts[1])
	return verified
}

func verifyMatch(ctx context.Context, client *http.Client, resMatch, token string) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", "https://api.trello.com/1/members/me?key="+resMatch+"&token="+token, nil)
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

	return "Trello is a collaboration tool that organizes your projects into boards. Trello API keys can be used to access and modify data within Trello."
}

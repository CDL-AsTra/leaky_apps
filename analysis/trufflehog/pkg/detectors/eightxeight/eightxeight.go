package eightxeight

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

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
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"8x8"}) + `\b([a-zA-Z0-9]{43})\b`)
	idPat  = regexp.MustCompile(detectors.PrefixRegex([]string{"8x8"}) + `\b([a-zA-Z0-9_]{18,30})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"8x8"}
}

// FromData will find and optionally verify EightxEight secrets in a given set of bytes.
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
			if len(idMatch) != 2 {
				continue
			}

			resIdMatch := strings.TrimSpace(idMatch[1])

			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_EightxEight,
				Raw:          []byte(resMatch),
				RawV2:        []byte(resMatch + resIdMatch),
			}

			if verify {
				verified, err := verifyMatch(ctx, client, resMatch, resIdMatch)
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
	return detectorspb.DetectorType_EightxEight
}

func (s Scanner) Description() string {
	return "8x8 is a provider of cloud-based communication services including voice, video, chat, and contact center solutions."
}

func (s Scanner) Verify(ctx context.Context, secret string) bool {
	parts := strings.Split(secret, ";-|")
	if len(parts) != 2 {
		return false
	}

	verified, _ := verifyMatch(ctx, client, parts[0], parts[1])
	return verified
}
func verifyMatch(ctx context.Context, client *http.Client, resMatch, resIdMatch string) (bool, error) {
	timeout := 10 * time.Second
	client.Timeout = timeout
	payload := strings.NewReader(`{"source":"abcde","destination":"+6512345678","text":"Hello World!","encoding":"AUTO"}`)
	req, err := http.NewRequestWithContext(ctx, "POST", fmt.Sprintf("https://sms.8x8.com/api/v1/subaccounts/%s/messages", resIdMatch), payload)
	if err != nil {
		return false, err
	}
	req.Header.Add("Content-Type", "application/json")
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

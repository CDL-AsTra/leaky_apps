package textmagic

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
	keyPat  = regexp.MustCompile(detectors.PrefixRegex([]string{"textmagic"}) + `\b([0-9A-Za-z]{30})\b`)
	userPat = regexp.MustCompile(detectors.PrefixRegex([]string{"textmagic"}) + `\b([0-9A-Za-z]{1,25})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"textmagic"}
}

// FromData will find and optionally verify Textmagic secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := keyPat.FindAllStringSubmatch(dataStr, -1)
	userMatches := userPat.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {
		if len(match) != 2 {
			continue
		}
		resMatch := strings.TrimSpace(match[1])

		for _, userMatch := range userMatches {
			if len(userMatch) != 2 {
				continue
			}
			resUser := strings.TrimSpace(userMatch[1])

			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_Textmagic,
				Raw:          []byte(resMatch),
				RawV2:        []byte(resMatch + resUser),
			}

			if verify {
				verified, err := verifyMatch(ctx, client, resMatch, resUser)
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
	return detectorspb.DetectorType_Textmagic
}

func (s Scanner) Verify(ctx context.Context, secret string) bool {
	parts := strings.Split(secret, ";-|")
	if len(parts) != 2 {
		return false
	}

	verified, _ := verifyMatch(ctx, client, parts[0], parts[1])
	return verified
}

func verifyMatch(ctx context.Context, client *http.Client, resMatch, resUser string) (bool, error) {
	data := fmt.Sprintf("%s:%s", resUser, resMatch)
	sEnc := b64.StdEncoding.EncodeToString([]byte(data))
	req, err := http.NewRequestWithContext(ctx, "GET", "https://rest.textmagic.com/api/v2/user", nil)
	if err != nil {
		return false, err
	}
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Authorization", fmt.Sprintf("Basic %s", sEnc))
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

	return "Textmagic is a service for sending and receiving text messages. Textmagic API keys can be used to access and manage text messaging services."
}

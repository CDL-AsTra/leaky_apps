package metaapi

import (
	"context"
	"fmt"
	"io"
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
	keyPat   = regexp.MustCompile(detectors.PrefixRegex([]string{"metaapi", "meta-api"}) + `\b([0-9a-f]{64})\b`)
	spellPat = regexp.MustCompile(detectors.PrefixRegex([]string{"metaapi", "meta-api"}) + `\b([0-9a-f]{24})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"metaapi", "meta-api"}
}

// FromData will find and optionally verify MetaAPI secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := keyPat.FindAllStringSubmatch(dataStr, -1)
	spellMatches := spellPat.FindAllStringSubmatch(dataStr, -1)

	for _, spellMatch := range spellMatches {
		if len(spellMatch) != 2 {
			continue
		}
		resSpellMatch := strings.TrimSpace(spellMatch[1])

		for _, match := range matches {
			if len(match) != 2 {
				continue
			}
			resMatch := strings.TrimSpace(match[1])

			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_MetaAPI,
				Raw:          []byte(resMatch),
				RawV2:        []byte(resMatch + resSpellMatch),
			}

			if verify {
				verified, err := verifyMatch(ctx, client, resMatch, resSpellMatch)
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
	return detectorspb.DetectorType_MetaAPI
}
func (s Scanner) Verify(ctx context.Context, secret string) bool {
	parts := strings.Split(secret, ";-|")
	if len(parts) != 2 {
		return false
	}

	verified, _ := verifyMatch(ctx, client, parts[0], parts[1])
	return verified
}
func verifyMatch(ctx context.Context, client *http.Client, resMatch, resSpellMatch string) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("https://api.meta-api.io/api/spells/%s/runSync", resSpellMatch), nil)
	if err != nil {
		return false, err
	}
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("apikey", resMatch)
	res, err := client.Do(req)
	if err == nil {
		defer res.Body.Close()
		body, errBody := io.ReadAll(res.Body)

		if errBody == nil {
			bodyStr := string(body)

			if res.StatusCode >= 200 && res.StatusCode < 300 && strings.Contains(bodyStr, `"success":true`) {
				return true, nil
			}
		}
	}
	return false, nil
}

func (s Scanner) Description() string {

	return "Detects MetaAPI credentials, which are typically API keys used for accessing the MetaAPI service."
}

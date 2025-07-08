package plivo

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
	idPat  = regexp.MustCompile(detectors.PrefixRegex([]string{"plivo"}) + `\b([A-Z]{20})\b`)
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"plivo"}) + `\b([A-Za-z0-9_-]{40})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"plivo"}
}

// FromData will find and optionally verify Plivo secrets in a given set of bytes.
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
			id := strings.TrimSpace(idMatch[1])
			stringResMatch := fmt.Sprintf("%s:%s", id, resMatch)

			decodeSecret := b64.StdEncoding.EncodeToString([]byte(stringResMatch))

			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_Plivo,
				Redacted:     id,
				Raw:          []byte(resMatch),
				RawV2:        []byte(id + ";-|" + decodeSecret),
			}
			if verify {
				verified, err := verifyMatch(ctx, client, id, decodeSecret)
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
	return detectorspb.DetectorType_Plivo
}

func (s Scanner) Verify(ctx context.Context, secret string) bool {
	parts := strings.Split(secret, ";-|")
	if len(parts) != 2 {
		return false
	}

	verified, _ := verifyMatch(ctx, client, parts[0], parts[1])
	return verified
}

func verifyMatch(ctx context.Context, client *http.Client, id, decodeSecret string) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", "https://api.plivo.com/v1/Account/"+id+"/Number/", nil)
	if err != nil {
		return false, err
	}
	req.Header.Add("Accept", "application/json")
	req.Header.Add("Authorization", fmt.Sprintf("Basic %s", decodeSecret))
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

	return "Plivo is a cloud-based communications platform that provides API services for voice and messaging. Plivo credentials can be used to access and manage these services."
}

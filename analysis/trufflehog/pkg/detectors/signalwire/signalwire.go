package signalwire

import (
	"context"
	b64 "encoding/base64"
	"fmt"
	"net/http"
	"strings"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct {
	detectors.DefaultMultiPartCredentialProvider
}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	client = detectors.DetectorHttpClientWithNoLocalAddresses

	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives.
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"signalwire"}) + `\b([0-9A-Za-z]{50})\b`)
	idPat  = regexp.MustCompile(detectors.PrefixRegex([]string{"signalwire"}) + `\b([0-9a-z]{8}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{12})\b`)
	urlPat = regexp.MustCompile(`\b([0-9a-z-]{3,64}\.signalwire\.com)\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"signalwire"}
}

// FromData will find and optionally verify Signalwire secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := keyPat.FindAllStringSubmatch(dataStr, -1)
	idMatches := idPat.FindAllStringSubmatch(dataStr, -1)
	urlMatches := urlPat.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {
		if len(match) != 2 {
			continue
		}
		resMatch := strings.TrimSpace(match[1])

		for _, idMatch := range idMatches {
			if len(idMatch) != 2 {
				continue
			}
			resID := strings.TrimSpace(idMatch[1])

			for _, urlMatch := range urlMatches {
				if len(urlMatch) != 2 {
					continue
				}
				resURL := strings.TrimSpace(urlMatch[1])

				s1 := detectors.Result{
					DetectorType: detectorspb.DetectorType_Signalwire,
					Raw:          []byte(resMatch),
					RawV2:        []byte(resMatch + ";-|" + resID + ";-|" + resURL),
				}

				if verify {
					verified, err := verifyMatch(ctx, client, resMatch, resID, resURL)
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
	return detectorspb.DetectorType_Signalwire
}

func (s Scanner) Verify(ctx context.Context, secret string) bool {
	parts := strings.Split(secret, ";-|")
	if len(parts) != 2 {
		return false
	}

	verified, _ := verifyMatch(ctx, client, parts[0], parts[1], parts[2])
	return verified
}

func verifyMatch(ctx context.Context, client *http.Client, resMatch, resID, resURL string) (bool, error) {
	data := fmt.Sprintf("%s:%s", resID, resMatch)
	sEnc := b64.StdEncoding.EncodeToString([]byte(data))
	req, err := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("https://%s/api/laml/2010-04-01/Accounts", resURL), nil)
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

	return "SignalWire is a communications platform as a service (CPaaS) provider. SignalWire credentials can be used to access and manage communication services such as voice, messaging, and video."
}

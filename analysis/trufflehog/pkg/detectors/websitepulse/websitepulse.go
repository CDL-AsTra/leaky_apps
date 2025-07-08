package websitepulse

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

// Ensure the Scanner satisfies the interface at compile time
var _ detectors.Detector = (*Scanner)(nil)

var (
	client = common.SaneHttpClient()

	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"websitepulse"}) + `\b([0-9a-f]{32})\b`)
	idPat  = regexp.MustCompile(detectors.PrefixRegex([]string{"websitepulse"}) + `\b([0-9a-zA-Z._]{4,22})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"websitepulse"}
}

// FromData will find and optionally verify Websitepulse secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := keyPat.FindAllStringSubmatch(dataStr, -1)
	idmatches := idPat.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {
		if len(match) != 2 {
			continue
		}
		resMatch := strings.TrimSpace(match[1])

		for _, idmatch := range idmatches {
			if len(idmatch) != 2 {
				continue
			}
			resIdMatch := strings.TrimSpace(idmatch[1])
			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_Websitepulse,
				Raw:          []byte(resMatch),
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
	return detectorspb.DetectorType_Websitepulse
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
	req, err := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("https://api.websitepulse.com/textserver.php?method=GetContacts&username=%s&key=%s", resIdMatch, resMatch), nil)
	if err != nil {
		return false, err
	}
	res, err := client.Do(req)
	if err == nil {
		defer res.Body.Close()
		bodyBytes, err := io.ReadAll(res.Body)
		if err != nil {
			return false, err
		}
		body := string(bodyBytes)

		if strings.Contains(body, "Active") {
			return true, nil
		}
	}
	return false, nil
}

func (s Scanner) Description() string {

	return "Websitepulse is a web-based service that monitors websites and servers. The keys and IDs can be used to access and manage monitoring configurations."
}

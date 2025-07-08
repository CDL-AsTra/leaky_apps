package yelp

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
	client *http.Client
}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	defaultClient = common.SaneHttpClient()

	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives.
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"yelp"}) + `\b([a-zA-Z0-9_\\=\.\-]{128})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"yelp"}
}

// FromData will find and optionally verify Yelp secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := keyPat.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {
		if len(match) != 2 {
			continue
		}
		resMatch := strings.TrimSpace(match[1])

		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_Yelp,
			Raw:          []byte(resMatch),
		}

		if verify {

			client := s.client
			if client == nil {
				client = defaultClient
			}
			verified, err := verifyMatch(ctx, client, resMatch)
			if err != nil {
				continue
			}
			s1.Verified = verified

		}

		results = append(results, s1)
	}

	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Yelp
}

func (s Scanner) Verify(ctx context.Context, secret string) bool {
	verified, _ := verifyMatch(ctx, defaultClient, secret)
	return verified
}

func verifyMatch(ctx context.Context, client *http.Client, resMatch string) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", "https://api.yelp.com/v3/businesses/search?term=delis&latitude=37.786882&longitude=-122.399972", nil)
	if err != nil {
		return false, err
	}
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", resMatch))
	res, err := client.Do(req)
	if err == nil {
		defer res.Body.Close()
		if res.StatusCode >= 200 && res.StatusCode < 300 {
			return true, nil
		} else if res.StatusCode == 401 || res.StatusCode == 403 {
			// The secret is determinately not verified (nothing to do)
		} else {
			fmt.Errorf("unexpected HTTP response status %d", res.StatusCode)
		}
	}
	return false, nil
}

func (s Scanner) Description() string {

	return "Yelp API keys allow access to Yelp's business data and services. Unauthorized access can lead to data breaches and misuse of Yelp's services."
}

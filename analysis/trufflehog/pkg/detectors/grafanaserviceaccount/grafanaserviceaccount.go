package grafanaserviceaccount

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct {
	client *http.Client
	detectors.DefaultMultiPartCredentialProvider
}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	defaultClient = detectors.DetectorHttpClientWithNoLocalAddresses
	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives.
	keyPat    = regexp.MustCompile(`\b(glsa_[0-9a-zA-Z_]{41})\b`)
	domainPat = regexp.MustCompile(`\b([a-zA-Z0-9-]+\.grafana\.net)\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"glsa_"}
}

// FromData will find and optionally verify Grafanaserviceaccount secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	keyMatches := keyPat.FindAllStringSubmatch(dataStr, -1)
	domainMatches := domainPat.FindAllStringSubmatch(dataStr, -1)

	for _, match := range keyMatches {
		if len(match) != 2 {
			continue
		}
		key := strings.TrimSpace(match[1])

		for _, domainMatch := range domainMatches {
			if len(domainMatch) != 2 {
				continue
			}
			domainRes := strings.TrimSpace(domainMatch[1])

			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_GrafanaServiceAccount,
				Raw:          []byte(key),
				RawV2:        []byte(fmt.Sprintf("%s;-|%s", key, domainRes)),
			}

			if verify {
				client := s.client
				if client == nil {
					client = defaultClient
				}
				verified, err := verifyMatch(ctx, client, key, domainRes)
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
	return detectorspb.DetectorType_GrafanaServiceAccount
}

func (s Scanner) Verify(ctx context.Context, secret string) bool {
	parts := strings.Split(secret, ";-|")
	if len(parts) != 2 {
		return false
	}

	verified, _ := verifyMatch(ctx, defaultClient, parts[0], parts[1])
	return verified
}
func verifyMatch(ctx context.Context, client *http.Client, key, domainRes string) (bool, error) {

	req, err := http.NewRequestWithContext(ctx, "GET", "https://"+domainRes+"/api/access-control/user/permissions", nil)
	if err != nil {
		return false, err
	}
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", key))
	res, err := client.Do(req)
	if err == nil {
		defer res.Body.Close()
		if res.StatusCode >= 200 && res.StatusCode < 300 {
			return true, nil
		} else if res.StatusCode == 401 {
			// The secret is determinately not verified (nothing to do)
		} else {
			err = fmt.Errorf("unexpected HTTP response status %d", res.StatusCode)
		}
	}
	return false, nil
}

func (s Scanner) Description() string {

	return "Grafana service accounts are used to authenticate and interact with Grafana's API. These credentials can be used to access and modify Grafana resources and settings."
}

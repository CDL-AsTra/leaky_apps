package pivotaltracker

import (
	"context"
	"net/http"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct{}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	// Get token at https://www.pivotaltracker.com/profile
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"pivotal"}) + `([a-z0-9]{32})`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"pivotal"}
}

// FromData will find and optionally verify PivotalTracker secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := keyPat.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {

		// First match is entire regex, second is the first group.
		if len(match) != 2 {
			continue
		}

		token := match[1]

		result := detectors.Result{
			DetectorType: detectorspb.DetectorType_PivotalTracker,
			Raw:          []byte(token),
		}

		if verify {
			verified, err := verifyMatch(ctx, token)
			if err != nil {
				continue
			}
			result.Verified = verified

		}

		results = append(results, result)
	}

	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_PivotalTracker
}

func (s Scanner) Verify(ctx context.Context, secret string) bool {
	verified, _ := verifyMatch(ctx, secret)
	return verified
}

func verifyMatch(ctx context.Context, resMatch string) (bool, error) {
	client := common.SaneHttpClient()
	// https://www.pivotaltracker.com/help/api/rest/v5#top
	req, err := http.NewRequestWithContext(ctx, "GET", "https://www.pivotaltracker.com/services/v5/me", nil)
	if err != nil {
		return false, err
	}
	req.Header.Add("Content-Type", "application/json; charset=utf-8")
	req.Header.Add("X-TrackerToken", resMatch)
	res, err := client.Do(req)
	if err == nil {
		res.Body.Close() // The request body is unused.

		if res.StatusCode >= 200 && res.StatusCode < 300 {
			return true, nil
		}
	}
	return false, nil
}

func (s Scanner) Description() string {

	return "PivotalTracker is a project management tool. PivotalTracker tokens can be used to access and manage projects and data within PivotalTracker."
}

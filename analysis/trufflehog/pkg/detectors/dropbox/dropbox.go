package dropbox

import (
	"context"
	"fmt"
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
	keyPat = regexp.MustCompile(`\b((sl\.[A-Za-z0-9\-\_]{130,140})|([a-z0-9]{11}(AAAAAAAAAA)[a-z0-9\-_=]{43}))\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"sl.", "AAAAAAAAAA"}
}

// FromData will find and optionally verify Dropbox secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {

	dataStr := string(data)

	matches := keyPat.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {

		result := detectors.Result{
			DetectorType: detectorspb.DetectorType_Dropbox,
			Raw:          []byte(match[1]),
		}

		if verify {

			verified, err := verifyMatch(ctx, match[1])
			if err != nil {
				continue
			}
			result.Verified = verified

		}

		results = append(results, result)
	}

	return
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Dropbox
}

func (s Scanner) Description() string {
	return "Dropbox is a file hosting service that offers cloud storage, file synchronization, personal cloud, and client software. Dropbox API keys can be used to access and manage files and folders in a Dropbox account."
}

func (s Scanner) Verify(ctx context.Context, secret string) bool {
	verified, _ := verifyMatch(ctx, secret)
	return verified
}
func verifyMatch(ctx context.Context, resMatch string) (bool, error) {
	baseURL := "https://api.dropboxapi.com/2/users/get_current_account"

	client := common.SaneHttpClient()

	req, err := http.NewRequestWithContext(ctx, "POST", baseURL, nil)
	if err != nil {
		return false, err
	}
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", resMatch))
	res, err := client.Do(req)
	if err == nil {
		res.Body.Close() // The request body is unused.

		// 200 means good key for get current user
		// 400 is bad (malformed)
		// 403 bad scope
		if res.StatusCode == http.StatusOK {
			return true, nil
		}
	}

	return false, nil
}

package bulksms

import (
	"context"
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
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"bulksms"}) + `\b([a-zA-Z0-9!@#$%^&*()]{29})\b`)
	idPat  = regexp.MustCompile(detectors.PrefixRegex([]string{"bulksms"}) + `\b([A-F0-9-]{37})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
func (s Scanner) Keywords() []string {
	return []string{"bulksms"}
}

// FromData will find and optionally verify Bulksms secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	var uniqueIds = make(map[string]struct{})
	var uniqueKeys = make(map[string]struct{})

	for _, match := range idPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueIds[match[1]] = struct{}{}
	}

	for _, match := range keyPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueKeys[match[1]] = struct{}{}
	}

	for id := range uniqueIds {
		for key := range uniqueKeys {
			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_Bulksms,
				Raw:          []byte(key),
				RawV2:        []byte(key + id),
			}

			if verify {
				verified, err := verifyMatch(ctx, client, key, id)
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

func verifyMatch(ctx context.Context, client *http.Client, key, id string) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", "https://api.bulksms.com/v1/messages", nil)
	if err != nil {
		return false, err
	}
	req.SetBasicAuth(id, key)
	res, err := client.Do(req)
	if err == nil {
		defer func() {
			_, _ = io.Copy(io.Discard, res.Body)
			_ = res.Body.Close()
		}()

		if res.StatusCode == http.StatusOK {
			return true, nil
		}
	}
	return false, nil

}

func (s Scanner) Verify(ctx context.Context, secret string) bool {
	parts := strings.Split(secret, ";-|")
	if len(parts) != 2 {
		return false
	}

	verified, _ := verifyMatch(ctx, client, parts[0], parts[1])
	return verified
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Bulksms
}

func (s Scanner) Description() string {
	return "BulkSMS is a service used for sending SMS messages in bulk. BulkSMS credentials can be used to access and send messages through the BulkSMS API."
}

package razorpay

import (
	"context"
	"encoding/json"
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

// The (`) character adds secondary encoding to parsed strings by Golang which also allows for escape sequences
var (
	client = common.SaneHttpClient()

	keyPat    = regexp.MustCompile(`(?i)\brzp_live_[A-Za-z0-9]{14}\b`)
	secretPat = regexp.MustCompile(`\b[A-Za-z0-9]{24}\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"rzp_live_"}
}

// FromData will find and optionally verify RazorPay secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	keyMatches := keyPat.FindAllString(dataStr, -1)

	for _, key := range keyMatches {
		secMatches := secretPat.FindAllString(dataStr, -1)

		for _, secret := range secMatches {

			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_RazorPay,
				Raw:          []byte(key),
				RawV2:        []byte(key + secret),
				Redacted:     key,
			}

			if verify {
				verified, err := verifyMatch(ctx, client, key, secret)
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
	return detectorspb.DetectorType_RazorPay
}

func (s Scanner) Verify(ctx context.Context, secret string) bool {
	parts := strings.Split(secret, ";-|")
	if len(parts) != 2 {
		return false
	}

	verified, _ := verifyMatch(ctx, client, parts[0], parts[1])
	return verified
}

func verifyMatch(ctx context.Context, client *http.Client, key, secret string) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", "https://api.razorpay.com/v1/items?count=1", nil)
	if err != nil {
		return false, err
	}
	req.SetBasicAuth(key, secret)
	res, err := client.Do(req)
	if err == nil {
		bodyBytes, err := io.ReadAll(res.Body)
		if err != nil {
			return false, err
		}
		defer res.Body.Close()
		if res.StatusCode >= 200 && res.StatusCode < 300 {
			if json.Valid(bodyBytes) {
				return true, nil
			}
		}
	}
	return false, nil
}

func (s Scanner) Description() string {

	return "RazorPay is a payment gateway service that allows businesses to accept, process, and disburse payments. RazorPay keys can be used to access and manage payment transactions."
}

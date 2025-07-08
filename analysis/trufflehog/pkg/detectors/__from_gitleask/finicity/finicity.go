package finicity

import (
	"context"
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

var (
	// Ensure the Scanner satisfies the interface at compile time.
	_ detectors.Detector = (*Scanner)(nil)

	defaultClient = common.SaneHttpClient()

	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives.
	keyPat  = regexp.MustCompile(detectors.PrefixRegex([]string{"finicity"}) + `\b([a-f0-9]{32})\b`)
	keyPat2 = regexp.MustCompile(detectors.PrefixRegex([]string{"finicity"}) + `\b([a-z0-9]{20})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"finicity"}
}

func (s Scanner) getClient() *http.Client {
	if s.client != nil {
		return s.client
	}
	return defaultClient
}

// FromData will find and optionally verify Abbysale secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := keyPat.FindAllStringSubmatch(dataStr, -1)
	matches2 := keyPat2.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {
		if len(match) != 2 {
			continue
		}
		resMatch := strings.TrimSpace(match[1])
		for _, match2 := range matches2 {

			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_Finicity,
				Raw:          []byte(resMatch),
				RawV2:        []byte(strings.TrimSpace(match2[1])),
			}

			if verify {
				client := s.getClient()
				isVerified, verificationErr := verifyMatch(ctx, client, resMatch)
				s1.Verified = isVerified
				s1.SetVerificationError(verificationErr, resMatch)
			}

			results = append(results, s1)
		}
	}

	return results, nil
}

func (s Scanner) Verify(ctx context.Context, secret string) bool {
	client := s.getClient()
	isVerified, _ := verifyMatch(ctx, client, secret)
	return isVerified
}

func verifyMatch(ctx context.Context, client *http.Client, resMatch string) (bool, error) {
	//TODO: imlempent
	return false, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Finicity
}

func (s Scanner) Description() string {
	return "Detected a Finicity API token, potentially risking financial data access and unauthorized financial operations."
}

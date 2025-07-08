package curl

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
	keyPat = regexp.MustCompile(`(\bcurl\b.*?[ \t\n\r](?:-H|--header)[ =]['"](?i)(?:Authorization:[ \t]?(?:Basic[ \t]([a-z0-9+\/]{8,}={0,3})|(?:Bearer|Token)[ \t]([\w=@.+\/-]{8,})|([\w=.+\/-]{8,})|(?:ApiKey|Token|X-API-KEY):[ \t]?([\w=@.+\/-]{8,}))['"]|\bcurl\b.*?[ \t\n\r](?:-u|--user)[ =]['"]?([^:]{3,}:[^'":]{3,})['"]?(?:\s|\z)))`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"curl"}
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

	for _, match := range matches {
		resMatch := strings.Join(match, "")
		resMatch = strings.ReplaceAll(resMatch, "\n", "")
		resMatch = strings.ReplaceAll(resMatch, "\r", "")

		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_Curl,
			Raw:          []byte(resMatch),
		}

		if verify {
			client := s.getClient()
			isVerified, verificationErr := verifyMatch(ctx, client, resMatch)
			s1.Verified = isVerified
			s1.SetVerificationError(verificationErr, resMatch)
		}

		results = append(results, s1)
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
	return detectorspb.DetectorType_Curl
}

func (s Scanner) Description() string {
	return "Identified curl auth credentials."
}

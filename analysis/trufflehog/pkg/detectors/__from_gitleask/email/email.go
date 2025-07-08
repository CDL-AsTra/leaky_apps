package email

import (
	"context"
	"net/http"
	"strings"

	regexp "github.com/wasilibs/go-re2"
	"golang.org/x/net/publicsuffix"

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
	keyPat = regexp.MustCompile(`\b([\w-\.]+@([\w-]+\.)+[\w-]{2,4})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"@"}
}

func (s Scanner) getClient() *http.Client {
	if s.client != nil {
		return s.client
	}
	return defaultClient
}

func (s Scanner) HasValidSuffix(email string) bool {
	if strings.Contains(email, "@android.com") {
		return false
	}
	// Extract the domain part of the email
	atIndex := strings.LastIndex(email, "@")
	if atIndex == -1 || atIndex+1 >= len(email) {
		return false
	}
	domain := email[atIndex+1:]

	// Answer from: https://stackoverflow.com/questions/66761032/is-there-a-way-to-extract-only-valid-domains-from-the-publicsuffix-library
	// Check if the domain has a valid public suffix (TLD)
	etld, im := publicsuffix.PublicSuffix(domain)
	if im { // ICANN managed
		return true
	} else if strings.IndexByte(etld, '.') >= 0 { // privately managed
		return false
	}
	return false
}

// FromData will find and optionally verify Abbysale secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := keyPat.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {
		if len(match) != 3 {
			continue
		}
		resMatch := strings.TrimSpace(match[1])
		if !s.HasValidSuffix(resMatch) {
			continue
		}
		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_EMail,
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
	return detectorspb.DetectorType_EMail
}

func (s Scanner) Description() string {
	return "Identified an Email address."
}

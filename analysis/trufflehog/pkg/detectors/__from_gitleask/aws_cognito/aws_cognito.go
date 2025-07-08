package aws_cognito

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
	keyPat = regexp.MustCompile(`\b((ap-east-1|ca-west-1|ap-south-2|eu-south-2|ap-southeast-4|eu-central-2|me-central-1|af-south-1|ap-southeast-3|ap-northeast-3|il-central-1|eu-south-1|me-south-1|sa-east-1|us-west-1|eu-north-1|eu-west-3|us-gov-west-1|ap-northeast-1|ap-northeast-2|ap-south-1|ap-southeast-1|ap-southeast-2|ca-central-1|cn-north-1|eu-central-1|eu-west-1|eu-west-2|us-east-1|us-east-2|us-west-2)\:[a-z0-9]{2,12}\-[a-z0-9]{2,12}\-[a-z0-9]{2,12}\-[a-z0-9]{2,12}\-[a-z0-9]{2,12})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"ap-east-1", "ca-west-1", "ap-south-2", "eu-south-2", "ap-southeast-4", "eu-central-2", "me-central-1", "af-south-1", "ap-southeast-3", "ap-northeast-3", "il-central-1", "eu-south-1", "me-south-1", "sa-east-1", "us-west-1", "eu-north-1", "eu-west-3", "us-gov-west-1", "ap-northeast-1", "ap-northeast-2", "ap-south-1", "ap-southeast-1", "ap-southeast-2", "ca-central-1", "cn-north-1", "eu-central-1", "eu-west-1", "eu-west-2", "us-east-1", "us-east-2", "us-west-2"}
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
		resMatch := strings.TrimSpace(match[0])
		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_AWS_Cognito,
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
	return detectorspb.DetectorType_AWS_Cognito
}

func (s Scanner) Description() string {
	return "Uncovered an AWS Cognito URL."
}

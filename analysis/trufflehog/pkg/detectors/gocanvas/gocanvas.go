package gocanvas

import (
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
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

var (
	client = common.SaneHttpClient()

	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives.
	keyPat   = regexp.MustCompile(detectors.PrefixRegex([]string{"gocanvas"}) + `\b([0-9A-Za-z/+]{43}=[ \r\n]{1})`)
	emailPat = regexp.MustCompile(detectors.PrefixRegex([]string{"gocanvas"}) + common.EmailPattern)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"gocanvas"}
}

// FromData will find and optionally verify GoCanvas secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := keyPat.FindAllStringSubmatch(dataStr, -1)

	uniqueEmailMatches := make(map[string]struct{})
	for _, match := range emailPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueEmailMatches[strings.TrimSpace(match[1])] = struct{}{}
	}

	for emailMatch := range uniqueEmailMatches {
		for _, match := range matches {
			if len(match) != 2 {
				continue
			}
			resMatch := strings.TrimSpace(match[1])

			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_GoCanvas,
				Raw:          []byte(resMatch),
				RawV2:        []byte(resMatch + emailMatch),
			}

			if verify {
				verified, err := verifyMatch(ctx, client, resMatch, emailMatch)
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

type Response struct {
	Error []struct {
		ErrorCode int `xml:"ErrorCode"`
	} `xml:"Error"`
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_GoCanvas
}

func (s Scanner) Verify(ctx context.Context, secret string) bool {
	parts := strings.Split(secret, ";-|")
	if len(parts) != 2 {
		return false
	}

	verified, _ := verifyMatch(ctx, client, parts[0], parts[1])
	return verified
}

func verifyMatch(ctx context.Context, client *http.Client, resMatch, emailMatch string) (bool, error) {

	payload := url.Values{}
	payload.Add("username", emailMatch)

	req, err := http.NewRequestWithContext(ctx, "GET", "https://www.gocanvas.com/apiv2/forms.xml", strings.NewReader(payload.Encode()))
	if err != nil {
		return false, err
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", resMatch))
	res, err := client.Do(req)
	if err == nil {
		defer res.Body.Close()
		body, errBody := io.ReadAll(res.Body)

		if errBody == nil {
			response := Response{}
			if err := xml.Unmarshal(body, &response); err != nil {
				return false, err
			}

			if res.StatusCode >= 200 && res.StatusCode < 300 && response.Error == nil {
				return true, nil
			}
		}
	}

	return false, nil
}

func (s Scanner) Description() string {

	return "GoCanvas is a platform for automating business processes using mobile forms. GoCanvas API keys can be used to access and modify data within the GoCanvas platform."
}

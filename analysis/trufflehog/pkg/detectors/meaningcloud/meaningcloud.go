package meaningcloud

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"strings"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct{}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	client = common.SaneHttpClient()

	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives.
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"meaningcloud"}) + `\b([a-z0-9]{32})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"meaningcloud"}
}

type response struct {
	DeepTime float64 `json:"deepTime"`
}

// FromData will find and optionally verify MeaningCloud secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := keyPat.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {
		if len(match) != 2 {
			continue
		}
		resMatch := strings.TrimSpace(match[1])

		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_MeaningCloud,
			Raw:          []byte(resMatch),
		}

		if verify {
			verified, err := verifyMatch(ctx, client, resMatch)
			if err != nil {
				continue
			}
			s1.Verified = verified

		}

		results = append(results, s1)
	}

	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_MeaningCloud
}

func (s Scanner) Verify(ctx context.Context, secret string) bool {
	verified, _ := verifyMatch(ctx, client, secret)
	return verified
}

func verifyMatch(ctx context.Context, client *http.Client, resMatch string) (bool, error) {
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	fw, err := writer.CreateFormField("key")
	if err != nil {
		return false, err
	}
	_, err = io.Copy(fw, strings.NewReader(resMatch))
	if err != nil {
		return false, err

	}
	fw, err = writer.CreateFormField("txt")
	if err != nil {
		return false, err

	}
	_, err = io.Copy(fw, strings.NewReader("test"))
	if err != nil {
		return false, err

	}
	writer.Close()
	req, err := http.NewRequestWithContext(ctx, "POST", "https://api.meaningcloud.com/lang-4.0/identification", bytes.NewReader(body.Bytes()))
	if err != nil {
		return false, err

	}
	req.Header.Add("Content-Type", writer.FormDataContentType())
	res, err := client.Do(req)
	if err == nil {
		defer res.Body.Close()
		if res.StatusCode >= 200 && res.StatusCode < 300 {
			var r response
			if err := json.NewDecoder(res.Body).Decode(&r); err != nil {
				return false, err

			}
			if r.DeepTime > 0 {
				return true, nil
			}
		}
	}
	return false, nil
}

func (s Scanner) Description() string {

	return "MeaningCloud is a text analytics service used to extract insights from unstructured content. MeaningCloud API keys can be used to access and utilize these text analytics services."
}

package pastebin

import (
	"bytes"
	"context"
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
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"pastebin"}) + `\b([a-zA-Z0-9_]{32})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"pastebin"}
}

// FromData will find and optionally verify Pastebin secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := keyPat.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {
		if len(match) != 2 {
			continue
		}
		resMatch := strings.TrimSpace(match[1])

		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_Pastebin,
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
	return detectorspb.DetectorType_Pastebin
}

func (s Scanner) Verify(ctx context.Context, secret string) bool {
	verified, _ := verifyMatch(ctx, client, secret)
	return verified
}

func verifyMatch(ctx context.Context, client *http.Client, resMatch string) (bool, error) {

	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	fw, err := writer.CreateFormField("api_dev_key")
	if err != nil {
		return false, err
	}
	_, err = io.Copy(fw, strings.NewReader(resMatch))
	if err != nil {
		return false, err

	}
	fw, err = writer.CreateFormField("api_paste_code")
	if err != nil {
		return false, err

	}
	_, err = io.Copy(fw, strings.NewReader("test"))
	if err != nil {
		return false, err

	}
	fw, err = writer.CreateFormField("api_option")
	if err != nil {
		return false, err

	}
	_, err = io.Copy(fw, strings.NewReader("paste"))
	if err != nil {
		return false, err

	}
	writer.Close()
	req, err := http.NewRequestWithContext(ctx, "POST", "https://pastebin.com/api/api_post.php", bytes.NewReader(body.Bytes()))
	if err != nil {
		return false, err

	}
	req.Header.Add("Content-Type", writer.FormDataContentType())
	res, err := client.Do(req)
	if err == nil {
		defer res.Body.Close()
		if res.StatusCode >= 200 && res.StatusCode < 300 {
			return true, nil
		}
	}
	return false, nil
}

func (s Scanner) Description() string {

	return "Pastebin is a website where users can store plain text. Pastebin keys can be used to access and manipulate stored data."
}

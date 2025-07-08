package infura

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

type Scanner struct{}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	client = common.SaneHttpClient()

	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives.
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"infura"}) + `\b([0-9a-z]{32})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"infura"}
}

// FromData will find and optionally verify Infura secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := keyPat.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {
		if len(match) != 2 {
			continue
		}
		resMatch := strings.TrimSpace(match[1])

		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_Infura,
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
	return detectorspb.DetectorType_Infura
}

func (s Scanner) Verify(ctx context.Context, secret string) bool {
	verified, _ := verifyMatch(ctx, client, secret)
	return verified
}

func verifyMatch(ctx context.Context, client *http.Client, resMatch string) (bool, error) {
	payload := strings.NewReader(`{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}`)
	req, err := http.NewRequestWithContext(ctx, "POST", "https://mainnet.infura.io/v3/"+resMatch, payload)
	if err != nil {
		return false, err
	}
	req.Header.Add("Content-Type", "application/json")
	res, err := client.Do(req)
	if err == nil {
		defer res.Body.Close()
		bodyBytes, err := io.ReadAll(res.Body)
		if err != nil {
			return false, err
		}
		body := string(bodyBytes)
		if strings.Contains(body, `"result"`) {
			return true, nil
		}
	}
	return false, nil
}

func (s Scanner) Description() string {

	return "Infura provides the infrastructure for decentralized applications to connect to the Ethereum blockchain. Infura keys can be used to interact with the Ethereum network."
}

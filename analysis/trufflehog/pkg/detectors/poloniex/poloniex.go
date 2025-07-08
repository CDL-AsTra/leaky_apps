package poloniex

import (
	"context"
	"crypto/hmac"
	"crypto/sha512"
	"encoding/hex"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

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
	keyPat    = regexp.MustCompile(detectors.PrefixRegex([]string{"poloniex"}) + `\b([0-9A-Z]{8}-[0-9A-Z]{8}-[0-9A-Z]{8}-[0-9A-Z]{8})\b`)
	secretPat = regexp.MustCompile(detectors.PrefixRegex([]string{"poloniex"}) + `\b([0-9a-f]{128})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"poloniex"}
}

// FromData will find and optionally verify Poloniex secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := keyPat.FindAllStringSubmatch(dataStr, -1)
	secretMatches := secretPat.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {
		if len(match) != 2 {
			continue
		}
		resMatch := strings.TrimSpace(match[1])

		for _, secretMatch := range secretMatches {
			if len(secretMatch) != 2 {
				continue
			}
			resSecretMatch := strings.TrimSpace(secretMatch[1])

			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_Poloniex,
				Raw:          []byte(resSecretMatch),
				RawV2:        []byte(resSecretMatch + resMatch),
			}

			if verify {
				verified, err := verifyMatch(ctx, client, resSecretMatch, resMatch)
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

func getPoloniexSignature(secret string, payload string) string {
	mac := hmac.New(sha512.New, []byte(secret))
	mac.Write([]byte(payload))
	macsum := mac.Sum(nil)
	return hex.EncodeToString(macsum)
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Poloniex
}

func (s Scanner) Verify(ctx context.Context, secret string) bool {
	parts := strings.Split(secret, ";-|")
	if len(parts) != 2 {
		return false
	}

	verified, _ := verifyMatch(ctx, client, parts[0], parts[1])
	return verified
}

func verifyMatch(ctx context.Context, client *http.Client, resSecretMatch, resMatch string) (bool, error) {
	timestamp := strconv.FormatInt(time.Now().Unix()*1000, 10)

	payload := url.Values{}
	payload.Add("command", "returnBalances")
	payload.Add("nonce", timestamp)

	signature := getPoloniexSignature(resSecretMatch, payload.Encode())

	req, err := http.NewRequestWithContext(ctx, "POST", "https://poloniex.com/tradingApi", strings.NewReader(payload.Encode()))
	if err != nil {
		return false, err
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Add("Key", resMatch)
	req.Header.Add("Sign", signature)
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

	return "Poloniex is a cryptocurrency exchange that allows users to trade various digital assets. Poloniex API keys can be used to access and manage account data and perform trading operations."
}

package shopify

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct {
	detectors.DefaultMultiPartCredentialProvider
}

// Ensure the Scanner satisfies the interface at compile time
var _ detectors.Detector = (*Scanner)(nil)
var _ detectors.CustomFalsePositiveChecker = (*Scanner)(nil)

var (
	client = detectors.DetectorHttpClientWithNoLocalAddresses

	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives.
	keyPat    = regexp.MustCompile(`\b(shppa_|shpat_|shpca_|shppa_|shpss_)([0-9A-Fa-f]{32})\b`)
	domainPat = regexp.MustCompile(`[a-zA-Z0-9-]+\.myshopify\.com`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"shppa_", "shpat_", "shpca_", "shppa_", "shpss_"}
}

// FromData will find and optionally verify Shopify secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	keyMatches := keyPat.FindAllString(dataStr, -1)
	domainMatches := domainPat.FindAllString(dataStr, -1)

	for _, match := range keyMatches {
		key := strings.TrimSpace(match)

		for _, domainMatch := range domainMatches {
			domainRes := strings.TrimSpace(domainMatch)

			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_Shopify,
				Redacted:     domainRes,
				Raw:          []byte(key),
				RawV2:        []byte(key + domainRes),
			}

			if verify {
				verified, err, extraData := verifyMatch(ctx, client, key, domainRes)
				if err != nil {
					continue
				}
				s1.Verified = verified
				s1.ExtraData = extraData

			}

			results = append(results, s1)

		}

	}

	return results, nil

}

func (s Scanner) IsFalsePositive(_ detectors.Result) (bool, string) {
	return false, ""
}

type shopifyTokenAccessScopes struct {
	AccessScopes []struct {
		Handle string `json:"handle"`
	} `json:"access_scopes"`
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Shopify
}

func (s Scanner) Verify(ctx context.Context, secret string) bool {
	parts := strings.Split(secret, ";-|")
	if len(parts) != 2 {
		return false
	}

	verified, _, _ := verifyMatch(ctx, client, parts[0], parts[1])
	return verified
}

func verifyMatch(ctx context.Context, client *http.Client, key, domainRes string) (bool, error, map[string]string) {
	extraData := map[string]string{}
	req, err := http.NewRequestWithContext(ctx, "GET", "https://"+domainRes+"/admin/oauth/access_scopes.json", nil)
	if err != nil {
		return false, err, extraData
	}
	req.Header.Add("X-Shopify-Access-Token", key)
	res, err := client.Do(req)
	if err == nil {
		if res.StatusCode >= 200 && res.StatusCode < 300 {
			shopifyTokenAccessScopes := shopifyTokenAccessScopes{}
			err := json.NewDecoder(res.Body).Decode(&shopifyTokenAccessScopes)
			if err == nil {
				var handleArray []string
				for _, handle := range shopifyTokenAccessScopes.AccessScopes {
					handleArray = append(handleArray, handle.Handle)

				}
				extraData["access_scopes"] = strings.Join(handleArray, ",")
				extraData["key"] = key
				extraData["store_url"] = domainRes
				return true, nil, extraData

			}
			res.Body.Close()
		}
	}
	return false, nil, extraData
}

func (s Scanner) Description() string {

	return "An ecommerce platform, API keys can be used to access customer data"
}

package spotifykey

import (
	"context"

	"golang.org/x/oauth2"

	"strings"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"

	"golang.org/x/oauth2/clientcredentials"

	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct {
	detectors.DefaultMultiPartCredentialProvider
}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives.
	secretPat = regexp.MustCompile(detectors.PrefixRegex([]string{"key", "secret"}) + `\b([A-Za-z0-9]{32})\b`)
	idPat     = regexp.MustCompile(detectors.PrefixRegex([]string{"id"}) + `\b([A-Za-z0-9]{32})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"spotify"}
}

// FromData will find and optionally verify SpotifyKey secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	ctx = context.WithValue(ctx, oauth2.HTTPClient, common.SaneHttpClient())

	dataStr := string(data)

	matches := secretPat.FindAllStringSubmatch(dataStr, -1)
	idMatches := idPat.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {
		if len(match) != 2 {
			continue
		}
		resMatch := strings.TrimSpace(match[1])
		for _, idMatch := range idMatches {
			if len(idMatch) != 2 {
				continue
			}
			idresMatch := strings.TrimSpace(idMatch[1])
			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_SpotifyKey,
				Raw:          []byte(resMatch),
				RawV2:        []byte(resMatch + idresMatch),
			}

			if verify {
				verified, err := verifyMatch(ctx, resMatch, idresMatch)
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

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_SpotifyKey
}

func (s Scanner) Verify(ctx context.Context, secret string) bool {
	parts := strings.Split(secret, ";-|")
	if len(parts) != 2 {
		return false
	}

	verified, _ := verifyMatch(ctx, parts[0], parts[1])
	return verified
}

func verifyMatch(ctx context.Context, resMatch, idresMatch string) (bool, error) {
	config := &clientcredentials.Config{
		ClientID:     idresMatch,
		ClientSecret: resMatch,
		TokenURL:     "https://accounts.spotify.com/api/token",
	}
	token, err := config.Token(ctx)
	if err == nil {
		if token.Type() == "Bearer" {
			return true, nil
		}
	}
	return false, nil
}

func (s Scanner) Description() string {

	return "Spotify API keys can be used to access and modify data within Spotify's services."
}

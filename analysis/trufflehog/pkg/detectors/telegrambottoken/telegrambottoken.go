package telegrambottoken

import (
	"context"
	"encoding/json"

	//	"fmt"
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

	// https://core.telegram.org/bots#6-botfather
	// thanks https://stackoverflow.com/questions/61868770/tegram-bot-api-token-format
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"telegram", "tgram://"}) + `\b([0-9]{8,10}:[a-zA-Z0-9_-]{35})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	// Apprise uses the `tgram://` url scheme.
	// https://github.com/caronc/apprise/wiki/Notify_telegram
	return []string{"telegram", "tgram"}
}

// FromData will find and optionally verify TelegramBotToken secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := keyPat.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {
		if len(match) != 2 {
			continue
		}
		key := strings.TrimSpace(match[1])

		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_TelegramBotToken,
			Raw:          []byte(key),
		}

		if verify {
			verified, err, extraData := verifyMatch(ctx, client, key)
			if err != nil {
				continue
			}
			s1.Verified = verified
			s1.ExtraData = extraData

		}

		results = append(results, s1)
	}

	return results, nil
}

// https://core.telegram.org/bots/api#making-requests
type apiResponse struct {
	Ok     bool          `json:"ok"`
	Result *userResponse `json:"result"`
}

// https://core.telegram.org/bots/api#user
type userResponse struct {
	IsBot    bool   `json:"is_bot"`
	Username string `json:"username"`
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_TelegramBotToken
}

func (s Scanner) Verify(ctx context.Context, secret string) bool {
	verified, _, _ := verifyMatch(ctx, client, secret)
	return verified
}

func verifyMatch(ctx context.Context, client *http.Client, resMatch string) (bool, error, map[string]string) {
	extraData := map[string]string{}
	// https://core.telegram.org/bots/api#getme
	req, err := http.NewRequestWithContext(ctx, "GET", "https://api.telegram.org/bot"+resMatch+"/getMe", nil)
	if err != nil {
		return false, err, extraData
	}

	res, err := client.Do(req)
	if err == nil {
		defer res.Body.Close()
		if res.StatusCode >= 200 && res.StatusCode < 300 {

			apiRes := apiResponse{}
			err := json.NewDecoder(res.Body).Decode(&apiRes)
			if err == nil && apiRes.Ok {
				extraData["username"] = apiRes.Result.Username

			}
			return true, nil, extraData
		}
	}
	return false, nil, extraData
}

func (s Scanner) Description() string {

	return "Telegram Bot API tokens are used to authenticate requests to the Telegram Bot API. They can be used to control and interact with Telegram bots."
}

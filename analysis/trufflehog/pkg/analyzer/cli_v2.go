package analyzer

import (
	"fmt"
	"strings"

	"github.com/alecthomas/kingpin/v2"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers/airbrake"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers/asana"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers/bitbucket"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers/github"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers/gitlab"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers/huggingface"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers/mailchimp"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers/mailgun"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers/mysql"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers/openai"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers/opsgenie"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers/postgres"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers/postman"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers/sendgrid"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers/shopify"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers/slack"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers/sourcegraph"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers/square"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers/stripe"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers/twilio"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/config"
)

var (
	// TODO: Add list of supported key types.
	analyzeKeyTypev2 *string
	//outputFile       *string
	logFile *string
	secret  *string
)

func Commandv2(app *kingpin.Application) *kingpin.CmdClause {
	cli := app.Command("analyze-v2", "Analyze API keys for fine-grained permissions information.")

	keyTypeHelp := fmt.Sprintf(
		"Type of key to analyze. Omit to interactively choose. Available key types: %s",
		strings.Join(analyzers.AvailableAnalyzers(), ", "),
	)
	// Lowercase the available analyzers.
	availableAnalyzers := make([]string, len(analyzers.AvailableAnalyzers()))
	for i, a := range analyzers.AvailableAnalyzers() {
		availableAnalyzers[i] = strings.ToLower(a)
	}
	analyzeKeyTypev2 = cli.Arg("key-type", keyTypeHelp).Enum(availableAnalyzers...)
	//outputFile = cli.Flag("output", "Output file to write the analysis results.").String()
	logFile = cli.Flag("logfile", "Logfile file to write the analysis results.").String()
	secret = cli.Flag("secret", "Secret key to analyze.").Required().String()

	return cli
}

func Runv2(cmd string) {

	config := &config.Config{}
	config.LogFile = *logFile
	//config.OutputFile = *outputFile
	config.LoggingEnabled = true
	parts := strings.Split(*secret, ";-|")

	switch strings.ToLower(*analyzeKeyTypev2) {
	case "github", "8":
		if strings.Contains(*secret, "@bitbucket.org") {
			bitbucket.AnalyzeAndPrintPermissions(config, *secret)
			return
		} else if strings.Contains(*secret, "@github.com") {
			github.AnalyzeAndPrintPermissions(config, *secret)
			return
		}

		github.AnalyzeAndPrintPermissions(config, *secret)
	case "sendgrid", "12":
		sendgrid.AnalyzeAndPrintPermissions(config, *secret)
	case "openai", "201":
		openai.AnalyzeAndPrintPermissions(config, *secret)
	case "postgres", "968":
		postgres.AnalyzeAndPrintPermissions(config, *secret)
	case "mysql":
		mysql.AnalyzeAndPrintPermissions(config, *secret)
	case "slack", "13":
		slack.AnalyzeAndPrintPermissions(config, *secret)
	case "twilio", "26":
		if len(parts) != 2 {
			return
		}
		twilio.AnalyzeAndPrintPermissions(config, parts[0], parts[1])
	case "airbrake", "125", "126":
		airbrake.AnalyzeAndPrintPermissions(config, *secret)
	case "huggingface", "926":
		huggingface.AnalyzeAndPrintPermissions(config, *secret)
	case "stripe", "16":
		stripe.AnalyzeAndPrintPermissions(config, *secret)
	case "gitlab", "9":
		gitlab.AnalyzeAndPrintPermissions(config, *secret)
	case "mailchimp", "20":
		mailchimp.AnalyzeAndPrintPermissions(config, *secret)
	case "postman", "118":
		postman.AnalyzeAndPrintPermissions(config, *secret)
	case "bitbucket":
		bitbucket.AnalyzeAndPrintPermissions(config, *secret)
	case "asana", "41":
		asana.AnalyzeAndPrintPermissions(config, *secret)
	case "mailgun", "34":
		mailgun.AnalyzeAndPrintPermissions(config, *secret)
	case "square", "14":
		square.AnalyzeAndPrintPermissions(config, *secret)
	case "sourcegraph", "928":
		sourcegraph.AnalyzeAndPrintPermissions(config, *secret)
	case "shopify", "902":
		if len(parts) != 2 {
			return
		}
		shopify.AnalyzeAndPrintPermissions(config, parts[0], parts[1])
	case "opsgenie", "875":
		opsgenie.AnalyzeAndPrintPermissions(config, *secret)
	}
}

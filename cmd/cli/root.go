package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html/template"
	"os"

	"github.com/bom-squad/protobom/internal"

	"github.com/bom-squad/protobom/pkg/formats"
	"github.com/bom-squad/protobom/pkg/writer/options"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

const (
	PROTOBOM_LONG_DESCRIPTION  = "Translate SBOM formats such as CycloneDX and SPDX"
	PROTOBOM_SHORT_DESCRIPTION = "Translate SBOM formats"
	ProtobomUserExample        = `  {{.appName}} [sbom] -f cyclonedx                   output CycloneDX
  {{.appName}} [sbom] -f cyclonedx -v 1.3            output CycloneDX version 1.3
  {{.appName}} [sbom] -f spdx                        output SPDX
  {{.appName}} [sbom] -f spdx -v 2.3                 output SPDX SBOM version 2.3
  {{.appName}} [sbom] -f spdx -e xml                 output XML encoded SPDX`
)

var (
	version         = "0.0.0"
	ApplicationName = "protobom"
	Cfg             internal.Application
)

var RootCmd = &cobra.Command{
	Version: version,
	Long:    PROTOBOM_LONG_DESCRIPTION,
	Use:     fmt.Sprintf("%s [sbom]", ApplicationName),
	Short:   PROTOBOM_SHORT_DESCRIPTION,
	Example: Tprintf(ProtobomUserExample, map[string]interface{}{
		"appName": ApplicationName,
	}),
	DisableAutoGenTag: true,
	CompletionOptions: cobra.CompletionOptions{DisableDefaultCmd: true},
	Args:              cobra.MinimumNArgs(1),
	Hidden:            false,
	SilenceUsage:      true,
	SilenceErrors:     false,
	PreRunE: func(cmd *cobra.Command, args []string) error {
		return nil
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		path := args[0]
		logrus.Infof("Running %s on %s", ApplicationName, path)

		v, err := json.MarshalIndent(Cfg, "", " ")
		if err != nil {
			return err
		}
		logrus.WithField("config", string(v)).Debugf("Protobom config")

		internal.Translate(path, &Cfg)
		return nil
	},
}

func init() {
	cobra.OnInitialize()

	RootCmd.PersistentFlags().StringVarP((*string)(&Cfg.WriterOpts.FormatOpt.FormatType), "format", "f", string(options.Default.FormatOpt.FormatType), fmt.Sprintf("Select format, Options=%s", formats.ListFormatType))
	RootCmd.PersistentFlags().StringVarP((*string)(&Cfg.WriterOpts.FormatOpt.FormatVersion), "version", "v", string(options.Default.FormatOpt.FormatVersion), fmt.Sprintf("Select version, Options=%s", formats.MapVersion))
	RootCmd.PersistentFlags().StringVarP((*string)(&Cfg.WriterOpts.FormatOpt.MimeFormat), "encoding", "e", string(options.Default.FormatOpt.MimeFormat), fmt.Sprintf("Select encoding, Options=%s", formats.ListEncoding))

}

func Execute() {
	if err := RootCmd.Execute(); err != nil {
		logrus.Errorf(fmt.Sprintf("%+v", err))
		os.Exit(1)
	}
}

func Tprintf(tmpl string, data map[string]interface{}) string {
	t := template.Must(template.New("").Parse(tmpl))
	buf := &bytes.Buffer{}
	if err := t.Execute(buf, data); err != nil {
		return ""
	}
	return buf.String()
}

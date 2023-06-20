package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html/template"
	"os"

	"github.com/bom-squad/protobom/pkg"
	"github.com/bom-squad/protobom/pkg/formats"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

const (
	PROTOBOM_LONG_DESCRIPTION = "Translate SBOM formats such as cyclonedx and spdx"
	PROTOBOM_SHORT_DESCRIPTION = "Translate SBOM formats"
	ProtobomUserExample        = `  {{.appName}} [sbom-path] [flags]

	{{.appName}} [sbom-path] -o cyclonedx output a cyclonedx sbom
	{{.appName}} [sbom-path] -o spdx output a spdx sbom`
)

var (
	version         = "0.0.0"
	ApplicationName = "protobom"
	Cfg             pkg.Application
	DefaultFormat   = formats.CDX14JSON
)

var RootCmd = &cobra.Command{
	Version: version,
	Long:    PROTOBOM_SHORT_DISCRIPTION,
	Use:     fmt.Sprintf("%s [TARGET]", ApplicationName),
	Short:   PROTOBOM__LONG_DISCRIPTION,
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

		pkg.Translate(path, &Cfg)
		return nil
	},
}

func init() {
	cobra.OnInitialize()

	RootCmd.PersistentFlags().StringVarP((*string)(&Cfg.WriterOpts.Format), "output-format", "o", string(DefaultFormat), fmt.Sprintf("Select output format, [%s]", formats.List))
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

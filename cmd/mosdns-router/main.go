package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/IrineSistiana/mosdns/v5/coremain"
	_ "github.com/IrineSistiana/mosdns/v5/plugin"
	"github.com/spf13/cobra"
	"mosdns-router/internal/buildinfo"
)

func init() {
	coremain.AddSubCmd(&cobra.Command{
		Use: "build-info",
		RunE: func(_ *cobra.Command, _ []string) error {
			return json.NewEncoder(os.Stdout).Encode(buildinfo.Snapshot())
		},
	})
}

func main() {
	if err := coremain.Run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

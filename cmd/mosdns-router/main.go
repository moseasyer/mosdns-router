package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/IrineSistiana/mosdns/v5/coremain"
	_ "github.com/IrineSistiana/mosdns/v5/plugin"
	"github.com/spf13/cobra"
	"mosdns-router/internal/buildinfo"

	// The router's own plugins: one forwards a query to the DNS servers the DHCP
	// client is currently configured with, swapping them while mosdns runs, and one
	// rewrites the addresses and the HTTPS records a response hands to a client.
	_ "mosdns-router/plugin/executable/cdn_rewrite"
	_ "mosdns-router/plugin/executable/dhcp_forward"
	_ "mosdns-router/plugin/executable/ttl_clamp"
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

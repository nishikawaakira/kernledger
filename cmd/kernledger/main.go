// Command kernledger is the orchestration CLI for Amazon Linux 2 IR.
//
// The binary itself does very little — it dispatches to subcommands
// implemented under internal/cli/. Distro adapters self-register via
// blank imports below; to add support for a new distro, write the
// adapter and add a blank import here.
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/nishikawaakira/kernledger/internal/cli"

	// Distro adapters. Order does not matter; each calls
	// distro.Register from its init().
	_ "github.com/nishikawaakira/kernledger/internal/distro/amazonlinux2"
	_ "github.com/nishikawaakira/kernledger/internal/distro/amazonlinux2023"
	_ "github.com/nishikawaakira/kernledger/internal/distro/ubuntu"
)

// Set via -ldflags at build time. See Makefile.
var (
	version = "dev"
	commit  = "none"
)

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Honor SIGINT/SIGTERM so an in-flight collect is cleanly aborted
	// (we still write partial output and a partial manifest).
	sigC := make(chan os.Signal, 1)
	signal.Notify(sigC, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigC
		cancel()
	}()

	os.Exit(cli.Run(ctx, version, commit, os.Args[1:]))
}

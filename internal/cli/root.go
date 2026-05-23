// Package cli wires together subcommands behind a minimal dispatcher.
// We deliberately avoid third-party CLI frameworks to keep the
// dependency tree empty for evidence-grade reproducibility.
package cli

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
)

// Subcommand is implemented by every top-level verb (inspect, acquire, ...).
type Subcommand interface {
	Name() string
	Synopsis() string
	SetFlags(*flag.FlagSet)
	Run(ctx context.Context, args []string) error
}

// Run dispatches argv to a registered subcommand.
// args is os.Args[1:].
func Run(ctx context.Context, version, commit string, args []string) int {
	cmds := registerAll(version, commit)

	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		printUsage(os.Stderr, cmds)
		if len(args) == 0 {
			return 2
		}
		return 0
	}
	if args[0] == "--version" || args[0] == "-v" {
		fmt.Printf("kernledger %s (%s)\n", version, commit)
		return 0
	}

	name := args[0]
	sub, ok := cmds[name]
	if !ok {
		fmt.Fprintf(os.Stderr, "unknown subcommand: %s\n\n", name)
		printUsage(os.Stderr, cmds)
		return 2
	}

	fs := flag.NewFlagSet("kernledger "+name, flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	sub.SetFlags(fs)
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	if err := sub.Run(ctx, fs.Args()); err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", name, err)
		return 1
	}
	return 0
}

func registerAll(version, commit string) map[string]Subcommand {
	cmds := map[string]Subcommand{}
	for _, c := range []Subcommand{
		newInspectCmd(version, commit),
		newCollectCmd(version, commit),
		newAcquireCmd(version, commit),
		newPackageCmd(version, commit),
		newSymbolsCmd(version, commit),
		newAnalyzeCmd(version, commit),
	} {
		cmds[c.Name()] = c
	}
	return cmds
}

func printUsage(w io.Writer, cmds map[string]Subcommand) {
	fmt.Fprintln(w, "kernledger — Amazon Linux 2 IR orchestration tool")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Usage: kernledger <subcommand> [flags] [args]")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Subcommands:")
	names := make([]string, 0, len(cmds))
	for n := range cmds {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		fmt.Fprintf(w, "  %-10s  %s\n", n, cmds[n].Synopsis())
	}
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Run 'kernledger <subcommand> -h' for per-command flags.")
}

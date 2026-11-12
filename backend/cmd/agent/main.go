// Command elyrn-agent is the robot entrance (docs/architecture/agents.md): an MCP server on
// stdio that speaks the elyrn. room protocol as one ordinary account.
//
//	elyrn-agent mcp   [--server URL]   MCP server on stdio (what MCP clients launch)
//	elyrn-agent init  --server URL     create the identity now (otherwise on first use)
//	elyrn-agent whoami                 public key and name; never the AccountNumber
//
// stdout carries MCP messages (mcp) or the one JSON result (init, whoami); logs go to stderr.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"io"
	"log"
	"os"
	"os/signal"
	"syscall"

	"elyrn/internal/agent"
	"elyrn/internal/cryptoengine"
	"elyrn/internal/mcp"
	"elyrn/internal/utils"
)

const (
	commandMCP    = "mcp"
	commandInit   = "init"
	commandWhoami = "whoami"
	flagServer    = "server"
	flagServerUse = "server origin: https://host[:port], or http:// for loopback or a .onion host"
	exitOK        = 0
	exitFailure   = 1
	exitUsage     = 2
	// codeSentenceFormat logs a failure as "<code>: <sentence>"
	codeSentenceFormat = "%s: %s"
)

var mainLogger = utils.NewLogger("AGENT-MAIN")

// The Agent is the tools' backend; this fails to compile if they drift apart.
var _ mcp.Backend = (*agent.Agent)(nil)

func main() {
	log.SetOutput(os.Stderr)
	log.SetFlags(0) // the logger stamps its own time
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	if len(args) == 0 {
		return usage()
	}
	if err := cryptoengine.SelfTest(); err != nil {
		mainLogger.Error("crypto engine self-test failed")
		return exitFailure
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	switch args[0] {
	case commandMCP:
		return withAgent(args[0], args[1:], false, func(a *agent.Agent) error { return serve(ctx, a) })
	case commandInit:
		return withAgent(args[0], args[1:], true, func(a *agent.Agent) error {
			result, err := a.Identity(ctx)
			return printResult(result, err)
		})
	case commandWhoami:
		return withAgent(args[0], args[1:], false, func(a *agent.Agent) error {
			result, err := a.Whoami()
			return printResult(result, err)
		})
	default:
		return usage()
	}
}

// withAgent parses the subcommand's flags, builds the agent and runs body with it.
func withAgent(name string, args []string, serverRequired bool, body func(*agent.Agent) error) int {
	flags := flag.NewFlagSet(name, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	server := ""
	if name != commandWhoami {
		flags.StringVar(&server, flagServer, "", flagServerUse)
	}
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 || (serverRequired && server == "") {
		return usage()
	}
	path, err := agent.DefaultIdentityPath()
	if err != nil {
		return report(err)
	}
	// whoami only reads the identity, so it runs beside an agent that holds the identity's lock
	a, err := agent.New(agent.Config{Server: server, IdentityPath: path, ReadOnly: name == commandWhoami})
	if err != nil {
		return report(err)
	}
	defer a.Close() // waits (bounded) for the call in flight, then releases the identity lock
	return report(body(a))
}

// serve runs the MCP server until stdin ends or a signal arrives. A signal cancels ctx, which
// cancels the tool call in flight; the caller's a.Close then waits for that call to return
// before wiping the agent, and only then does the process exit.
func serve(ctx context.Context, a *agent.Agent) error {
	if err := a.RequireServer(); err != nil {
		return err
	}
	done := make(chan error, 1)
	go func() { done <- mcp.Serve(ctx, os.Stdin, os.Stdout, a) }()
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		mainLogger.Info("stopping on signal")
		return nil
	}
}

func printResult(result *agent.IdentityResult, err error) error {
	if err != nil {
		return err
	}
	raw, err := json.Marshal(result)
	if err != nil {
		return agent.Fail(agent.CodeInternal, err)
	}
	_, err = os.Stdout.Write(append(raw, '\n'))
	return err
}

// report logs the code and sentence of a failure (never its cause) and picks the exit code.
func report(err error) int {
	if err == nil {
		return exitOK
	}
	code := agent.CodeOf(err)
	mainLogger.Error(codeSentenceFormat, code, agent.Sentence(code))
	return exitFailure
}

func usage() int {
	mainLogger.Error(codeSentenceFormat, agent.CodeUsage, agent.Sentence(agent.CodeUsage))
	return exitUsage
}

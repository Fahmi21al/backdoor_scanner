package attacksurface

import (
	"fmt"

	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
	"github.com/projectdiscovery/httpx/runner"
)

type HttpxRunner struct {
	Options *runner.Options
}

// NewHttpxRunner initializes a new Httpx runner
func NewHttpxRunner(targets []string) *HttpxRunner {
	gologger.DefaultLogger.SetMaxLevel(levels.LevelSilent)

	var targetSlice goflags.StringSlice
	for _, t := range targets {
		targetSlice.Set(t)
	}

	options := &runner.Options{
		Methods:         "GET",
		InputTargetHost: targetSlice,
		TechDetect:      true,
		ExtractTitle:    true,
		StatusCode:      true,
		Silent:          true,
		Retries:         1,
		Threads:         10,
		Timeout:         10,
	}

	return &HttpxRunner{
		Options: options,
	}
}

func (h *HttpxRunner) Profile() ([]runner.Result, error) {
	var results []runner.Result

	h.Options.OnResult = func(r runner.Result) {
		if r.Err == nil {
			results = append(results, r)
		}
	}

	if err := h.Options.ValidateOptions(); err != nil {
		return nil, fmt.Errorf("invalid httpx options: %w", err)
	}

	httpxRunner, err := runner.New(h.Options)
	if err != nil {
		return nil, fmt.Errorf("could not create httpx runner: %w", err)
	}
	defer httpxRunner.Close()

	httpxRunner.RunEnumeration()

	return results, nil
}

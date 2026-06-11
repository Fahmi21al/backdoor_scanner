package attacksurface

import (
	"fmt"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
	"github.com/projectdiscovery/katana/pkg/engine/standard"
	"github.com/projectdiscovery/katana/pkg/output"
	"github.com/projectdiscovery/katana/pkg/types"
)

// KatanaRunner wraps the ProjectDiscovery Katana crawler
type KatanaRunner struct {
	Options *types.Options
}

// NewKatanaRunner initializes a new Katana runner with default settings for SFS
func NewKatanaRunner(targetURL string, maxDepth int) *KatanaRunner {
	// Disable verbose output from katana
	gologger.DefaultLogger.SetMaxLevel(levels.LevelSilent)

	options := &types.Options{
		MaxDepth:               maxDepth,
		FieldScope:             "rdn",
		Concurrency:            10,
		Parallelism:            10,
		Timeout:                10,
		Retries:                1,
		Silent:                 true,
		Strategy:               "depth-first",
		Resolvers:              []string{"8.8.8.8", "1.1.1.1", "8.8.4.4"},
		ScrapeJSResponses:      true,
		ScrapeJSLuiceResponses: true,
		FormExtraction:         true,
		XhrExtraction:          true,
		AutomaticFormFill:      true,
		KnownFiles:             "all",
	}
	options.URLs.Set(targetURL)

	return &KatanaRunner{
		Options: options,
	}
}

// Crawl runs the crawler and returns a list of discovered URLs
func (k *KatanaRunner) Crawl(rootURL string) ([]string, error) {
	var discovered []string

	k.Options.OnResult = func(res output.Result) {
		if res.Request != nil && res.Request.URL != "" {
			discovered = append(discovered, res.Request.URL)
		}
	}

	crawlerOptions, err := types.NewCrawlerOptions(k.Options)
	if err != nil {
		return nil, fmt.Errorf("could not create crawler options: %w", err)
	}
	defer crawlerOptions.Close()

	crawler, err := standard.New(crawlerOptions)
	if err != nil {
		return nil, fmt.Errorf("could not create katana crawler: %w", err)
	}
	defer crawler.Close()

	if err := crawler.Crawl(rootURL); err != nil {
		return nil, fmt.Errorf("could not execute crawling: %w", err)
	}

	return discovered, nil
}

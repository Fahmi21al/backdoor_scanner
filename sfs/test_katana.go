package main

import (
	"fmt"
	"log"

	"github.com/projectdiscovery/katana/pkg/engine/standard"
	"github.com/projectdiscovery/katana/pkg/output"
	"github.com/projectdiscovery/katana/pkg/types"
)

func main() {
	target := "https://pmb.riau.go.id/"
	options := &types.Options{
		MaxDepth:               3,
		FieldScope:             "rdn",
		Concurrency:            10,
		Parallelism:            10,
		Timeout:                10,
		Retries:                1,
		Silent:                 true,
		Strategy:               "depth-first",
		Resolvers:              []string{"8.8.8.8", "1.1.1.1", "8.8.4.4"},
		ScrapeJSResponses:      true,
		KnownFiles:             "all",
		Headless:               true,
	}
	options.URLs.Set(target)

	var discovered []string

	options.OnResult = func(res output.Result) {
		if res.Request != nil && res.Request.URL != "" {
			discovered = append(discovered, res.Request.URL)
		}
	}

	crawlerOptions, err := types.NewCrawlerOptions(options)
	if err != nil {
		log.Fatalf("Error: %v", err)
	}
	defer crawlerOptions.Close()

	crawler, err := standard.New(crawlerOptions)
	if err != nil {
		log.Fatalf("Error: %v", err)
	}
	defer crawler.Close()

	if err := crawler.Crawl(target); err != nil {
		log.Fatalf("Error: %v", err)
	}

	fmt.Printf("Discovered %d urls\n", len(discovered))
	for _, u := range discovered {
		fmt.Println(u)
	}
}

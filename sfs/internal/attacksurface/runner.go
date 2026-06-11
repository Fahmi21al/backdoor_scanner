package attacksurface

import (
	"fmt"
	"log"
)

type AttackSurfaceResult struct {
	CrawledURLs []string
	LiveHosts   []HttpxResult
}

type HttpxResult struct {
	URL        string
	Title      string
	StatusCode int
	Tech       []string
	Server     string
}

// Discover runs Katana to find endpoints and Httpx to profile technologies
func Discover(targetURL string, maxDepth int) (*AttackSurfaceResult, error) {
	log.Printf("[AttackSurface] Starting discovery on %s", targetURL)

	// 1. Crawl with Katana
	katana := NewKatanaRunner(targetURL, maxDepth)
	urls, err := katana.Crawl(targetURL)
	if err != nil {
		return nil, fmt.Errorf("katana crawl failed: %w", err)
	}
	log.Printf("[AttackSurface] Katana discovered %d URLs", len(urls))

	// If no URLs found, just fallback to root
	if len(urls) == 0 {
		urls = append(urls, targetURL)
	}

	// 2. Profile with Httpx
	httpx := NewHttpxRunner(urls)
	hResults, err := httpx.Profile()
	if err != nil {
		return nil, fmt.Errorf("httpx profile failed: %w", err)
	}
	log.Printf("[AttackSurface] Httpx profiled %d live endpoints", len(hResults))

	var liveHosts []HttpxResult
	for _, r := range hResults {
		liveHosts = append(liveHosts, HttpxResult{
			URL:        r.URL,
			Title:      r.Title,
			StatusCode: r.StatusCode,
			Tech:       r.Technologies,
			Server:     r.WebServer,
		})
	}

	return &AttackSurfaceResult{
		CrawledURLs: urls,
		LiveHosts:   liveHosts,
	}, nil
}

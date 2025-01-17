package java

import (
	"context"
	"fmt"
	v5 "github.com/anchore/grype/grype/db/v5"
	"github.com/anchore/grype/grype/db/v5/search"
	"github.com/anchore/grype/grype/distro"
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	syftPkg "github.com/anchore/syft/syft/pkg"
	"net/http"
	"sync"
)

const (
	sha1Query = `1:"%s"`
)

type Matcher struct {
	MavenSearcher
	cfg   MatcherConfig
	cache sync.Map // Cache for Maven SHA lookups
}

type ExternalSearchConfig struct {
	SearchMavenUpstream bool
	MavenBaseURL        string
}

type MatcherConfig struct {
	ExternalSearchConfig
	UseCPEs bool
}

func NewJavaMatcher(cfg MatcherConfig) *Matcher {
	return &Matcher{
		cfg: cfg,
		MavenSearcher: &mavenSearch{
			client:  http.DefaultClient,
			baseURL: cfg.MavenBaseURL,
		},
	}
}

func (m *Matcher) PackageTypes() []syftPkg.Type {
	return []syftPkg.Type{syftPkg.JavaPkg, syftPkg.JenkinsPluginPkg}
}

func (m *Matcher) Type() match.MatcherType {
	return match.JavaMatcher
}

func (m *Matcher) Match(store v5.VulnerabilityProvider, d *distro.Distro, p pkg.Package) ([]match.Match, error) {
	if p.Name == "derby" {
		fmt.Printf("\n=== Java Matcher Details ===\n")
		fmt.Printf("Package: %s v%s\n", p.Name, p.Version)
		fmt.Printf("CPEs enabled: %v\n", m.cfg.UseCPEs)
		fmt.Printf("Search Maven Upstream: %v\n", m.cfg.SearchMavenUpstream)
	}

	var matches []match.Match
	if m.cfg.SearchMavenUpstream {
		if p.Name == "derby" {
			fmt.Printf("\nTrying upstream Maven matching\n")
		}
		upstreamMatches, err := m.matchUpstreamMavenPackages(store, d, p)
		if err != nil {
			if p.Name == "derby" {
				fmt.Printf("Failed upstream match: %v\n", err)
			}
		} else {
			if p.Name == "derby" {
				fmt.Printf("Found %d upstream matches\n", len(upstreamMatches))
			}
			matches = append(matches, upstreamMatches...)
		}
	}

	criteria := search.CommonCriteria
	if m.cfg.UseCPEs {
		if p.Name == "derby" {
			fmt.Printf("\nAdding CPE criteria to search\n")
		}
		criteria = append(criteria, search.ByCPE)
	}
	if p.Name == "derby" {
		fmt.Printf("\nSearching by criteria:\n")
	}
	for _, c := range criteria {
		if p.Name == "derby" {
			fmt.Printf("- %T\n", c)
		}
	}

	criteriaMatches, err := search.ByCriteria(store, d, p, m.Type(), criteria...)
	if err != nil {
		return nil, fmt.Errorf("failed to match by exact package: %w", err)
	}
	if p.Name == "derby" {
		fmt.Printf("\nFound %d matches by criteria\n", len(criteriaMatches))
	}
	if len(criteriaMatches) > 0 {
		for _, m := range criteriaMatches {

			if p.Name == "derby" {
				fmt.Printf("Match: %s\n", m.Vulnerability.ID)
				//fmt.Printf("  Type: %v\n", m.Type)
				fmt.Printf("  Package: %s v%s\n", m.Package.Name, m.Package.Version)
				//fmt.Printf("  Criteria used: %v\n", m.MatchDetail.SearchedBy)
			}
		}
	}

	matches = append(matches, criteriaMatches...)
	if p.Name == "derby" {
		fmt.Printf("\nTotal matches: %d\n", len(matches))
	}
	return matches, nil
}

func (m *Matcher) matchUpstreamMavenPackages(store v5.VulnerabilityProvider, d *distro.Distro, p pkg.Package) ([]match.Match, error) {
	var matches []match.Match

	ctx := context.Background()
	if metadata, ok := p.Metadata.(pkg.JavaMetadata); ok {
		for _, digest := range metadata.ArchiveDigests {
			if digest.Algorithm != "sha1" {
				continue
			}

			// Check cache
			if cachedPkg, ok := m.cache.Load(digest.Value); ok {
				if pkg, ok := cachedPkg.(*pkg.Package); ok && pkg != nil {
					indirectMatches, err := search.ByPackageLanguage(store, d, *pkg, m.Type())
					if err != nil {
						return nil, err
					}
					matches = append(matches, indirectMatches...)
					continue
				}
			}

			fmt.Printf("Looking up Maven package by SHA-1: %s\n", digest.Value)
			// Get package with built-in retries
			indirectPackage, err := m.GetMavenPackageBySha(ctx, digest.Value)
			if err != nil {
				m.cache.Store(digest.Value, nil)
				return nil, err
			}

			m.cache.Store(digest.Value, indirectPackage)
			indirectMatches, err := search.ByPackageLanguage(store, d, *indirectPackage, m.Type())
			if err != nil {
				return nil, err
			}
			matches = append(matches, indirectMatches...)
		}
	}

	match.ConvertToIndirectMatches(matches, p)
	return matches, nil
}

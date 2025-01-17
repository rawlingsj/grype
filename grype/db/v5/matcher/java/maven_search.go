package java

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"sort"
	"time"

	"github.com/anchore/grype/grype/pkg"
	syftPkg "github.com/anchore/syft/syft/pkg"
	"golang.org/x/time/rate"
)

type MavenSearcher interface {
	GetMavenPackageBySha(context.Context, string) (*pkg.Package, error)
}

type mavenSearch struct {
	client  *http.Client
	baseURL string
	limiter *rate.Limiter
	//mu      sync.RWMutex
	//lastError  time.Time
	//errorCount int
}

func NewMavenSearch(client *http.Client, baseURL string) *mavenSearch {
	if client == nil {
		client = &http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				MaxIdleConns:        100,
				MaxIdleConnsPerHost: 100,
				IdleConnTimeout:     30 * time.Second,
				DisableCompression:  true,
				ForceAttemptHTTP2:   false,
				//DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				//	start := time.Now()
				//	d := &net.Dialer{
				//		Timeout:   10 * time.Second,
				//		KeepAlive: 15 * time.Second,
				//	}
				//	conn, err := d.DialContext(ctx, network, addr)
				//	log.Printf("Dial: addr=%s localAddr=%v remoteAddr=%v took=%v err=%v",
				//		addr,
				//		conn.LocalAddr(),
				//		conn.RemoteAddr(),
				//		time.Since(start),
				//		err)
				//	return conn, err
				//},
			},
		}
	}
	return &mavenSearch{
		client:  client,
		baseURL: baseURL,

		// 200 fails after 4.5 mins
		limiter: rate.NewLimiter(rate.Every(300*time.Millisecond), 1),
	}
}

type mavenAPIResponse struct {
	Response struct {
		NumFound int `json:"numFound"`
		Docs     []struct {
			ID           string `json:"id"`
			GroupID      string `json:"g"`
			ArtifactID   string `json:"a"`
			Version      string `json:"v"`
			P            string `json:"p"`
			VersionCount int    `json:"versionCount"`
		} `json:"docs"`
	} `json:"response"`
}

//
//func (ms *mavenSearch) adjustRateLimit() {
//	ms.mu.Lock()
//	defer ms.mu.Unlock()
//
//	if time.Since(ms.lastError) > 5*time.Minute {
//		ms.errorCount = 0
//		ms.limiter.SetLimit(rate.Every(1 * time.Second))
//		return
//	}
//
//	newDelay := time.Duration(ms.errorCount+1) * 2 * time.Second
//	ms.limiter.SetLimit(rate.Every(newDelay))
//}
//
//func (ms *mavenSearch) recordError() {
//	ms.mu.Lock()
//	defer ms.mu.Unlock()
//	ms.lastError = time.Now()
//	ms.errorCount++
//}

func (ms *mavenSearch) GetMavenPackageBySha(ctx context.Context, sha1 string) (*pkg.Package, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	if err := ms.limiter.Wait(ctx); err != nil {
		return nil, fmt.Errorf("rate limiter error: %w", err)
	}

	return ms.tryGetMavenPackage(ctx, sha1)

}

func (ms *mavenSearch) tryGetMavenPackage(ctx context.Context, sha1 string) (*pkg.Package, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, ms.baseURL, nil)
	if err != nil {
		return nil, fmt.Errorf("unable to initialize HTTP client: %w", err)
	}

	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Connection", "keep-alive")

	q := req.URL.Query()
	q.Set("q", fmt.Sprintf("1:\"%s\"", sha1))
	q.Set("core", "gav")
	q.Set("rows", "1")
	q.Set("wt", "json")
	req.URL.RawQuery = q.Encode()

	resp, err := ms.client.Do(req)
	log.Printf("Response: status=%s err=%v", resp.Status, err)

	if err != nil {
		return nil, fmt.Errorf("sha1 search error: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("status %s from %s (body: %s)", resp.Status, req.URL.String(), body)
	}

	var res mavenAPIResponse
	if err = json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return nil, fmt.Errorf("json decode error: %w", err)
	}

	if len(res.Response.Docs) == 0 {
		return nil, fmt.Errorf("digest %s: %w", sha1, errors.New("no artifact found"))
	}

	docs := res.Response.Docs
	sort.Slice(docs, func(i, j int) bool {
		return docs[i].ID < docs[j].ID
	})
	d := docs[0]

	return &pkg.Package{
		Name:     fmt.Sprintf("%s:%s", d.GroupID, d.ArtifactID),
		Version:  d.Version,
		Language: syftPkg.Java,
		Metadata: pkg.JavaMetadata{
			PomArtifactID: d.ArtifactID,
			PomGroupID:    d.GroupID,
		},
	}, nil
}

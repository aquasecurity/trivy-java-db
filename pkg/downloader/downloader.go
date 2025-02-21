package downloader

import (
	"context"
	"io"
	"log/slog"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/hashicorp/go-retryablehttp"
	"golang.org/x/xerrors"
)

const indexesURL = "https://repo.maven.apache.org/maven2/.index/"

type Option struct {
	RootUrl  string
	CacheDir string
}

type Downloader struct {
	http       *retryablehttp.Client
	url        string
	archiveDir string
}

func NewDownloader(opt Option) (Downloader, error) {
	client := retryablehttp.NewClient()
	client.RetryMax = 15
	client.Logger = slog.Default()
	client.RetryWaitMin = 1 * time.Minute
	client.RetryWaitMax = 5 * time.Minute
	client.Backoff = retryablehttp.LinearJitterBackoff
	client.ResponseLogHook = func(_ retryablehttp.Logger, resp *http.Response) {
		if resp.StatusCode != http.StatusOK {
			slog.Warn("Unexpected http response", slog.String("url", resp.Request.URL.String()), slog.String("status", resp.Status))
		}
	}
	client.ErrorHandler = func(resp *http.Response, err error, numTries int) (*http.Response, error) {
		logger := slog.Default()
		if resp != nil {
			logger = slog.With(slog.String("url", resp.Request.URL.String()), slog.Int("status_code", resp.StatusCode),
				slog.Int("num_tries", numTries))
		}

		if err != nil {
			logger = logger.With(slog.String("error", err.Error()))
		}
		logger.Error("HTTP request failed after retries")
		return resp, xerrors.Errorf("HTTP request failed after retries: %w", err)
	}

	if opt.RootUrl == "" {
		opt.RootUrl = indexesURL
	}

	archiveDir := filepath.Join(opt.CacheDir, "archives")

	if err := os.MkdirAll(archiveDir, os.ModePerm); err != nil {
		return Downloader{}, err
	}
	slog.Info("Archives dir", slog.String("path", archiveDir))

	return Downloader{
		http:       client,
		url:        opt.RootUrl,
		archiveDir: archiveDir,
	}, nil
}

func (d Downloader) Download() error {
	ctx := context.Background()
	resp, err := d.httpGet(ctx, d.url)
	if err != nil {
		return xerrors.Errorf("http get error: %w", err)
	}
	defer resp.Body.Close()

	// There are cases when url doesn't exist
	// e.g. https://repo.maven.apache.org/maven2/io/springboot/ai/spring-ai-anthropic/
	if resp.StatusCode != http.StatusOK {
		return nil
	}

	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		return xerrors.Errorf("can't create new goquery doc: %w", err)
	}

	var indexesLinks []string
	doc.Find("a").Each(func(i int, selection *goquery.Selection) {
		link := selection.Text()
		// Don't save main archive
		if !strings.HasSuffix(link, ".gz") || link == "nexus-maven-repository-index.gz" {
			return
		}
		l, _ := url.JoinPath(d.url, link)
		indexesLinks = append(indexesLinks, l)
	})

	for _, link := range indexesLinks {
		resp, err = d.httpGet(ctx, link)
		if err != nil {
			return xerrors.Errorf("http get error: %w", err)
		}

		archivePath := filepath.Join(d.archiveDir, path.Base(link))
		f, err := os.Create(archivePath)
		if err != nil {
			return xerrors.Errorf("can't create file %s: %w", archivePath, err)
		}

		slog.Info("Saving archive", slog.String("path", archivePath))
		if _, err = io.Copy(f, resp.Body); err != nil {
			return xerrors.Errorf("can't copy file %s: %w", archivePath, err)
		}
	}
	return nil
}

func (d Downloader) httpGet(ctx context.Context, url string) (*http.Response, error) {
	// Sleep for a while to avoid 429 error
	randomSleep()

	req, err := retryablehttp.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, xerrors.Errorf("unable to create a HTTP request: %w", err)
	}
	resp, err := d.http.Do(req)
	if err != nil {
		return nil, xerrors.Errorf("http error (%s): %w", url, err)
	}
	return resp, nil
}

func randomSleep() {
	// Seed rand
	r := rand.New(rand.NewSource(int64(time.Now().Nanosecond())))
	time.Sleep(time.Duration(r.Float64() * float64(100*time.Millisecond)))
}

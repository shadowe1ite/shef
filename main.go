package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/blang/semver"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/log"
	"github.com/corpix/uarand"
	"github.com/rhysd/go-github-selfupdate/selfupdate"
)

const version = "2.2.3"

var shodanFacets = []string{
	"asn", "bitcoin.ip", "bitcoin.ip_count", "bitcoin.port", "bitcoin.user_agent",
	"bitcoin.version", "city", "cloud.provider", "cloud.region", "cloud.service",
	"country", "cpe", "device", "domain", "has_screenshot", "hash",
	"http.component", "http.component_category", "http.dom_hash", "http.favicon.hash",
	"http.headers_hash", "http.html_hash", "http.robots_hash", "http.server_hash",
	"http.status", "http.title", "http.title_hash", "http.waf", "ip", "isp",
	"link", "mongodb.database.name", "ntp.ip", "ntp.ip_count", "ntp.more",
	"ntp.port", "org", "os", "port", "postal", "product", "redis.key",
	"region", "rsync.module", "screenshot.hash", "screenshot.label",
	"snmp.contact", "snmp.location", "snmp.name", "ssh.cipher", "ssh.fingerprint",
	"ssh.hassh", "ssh.mac", "ssh.type", "ssl.alpn", "ssl.cert.alg",
	"ssl.cert.expired", "ssl.cert.extension", "ssl.cert.fingerprint",
	"ssl.cert.issuer.cn", "ssl.cert.pubkey.bits", "ssl.cert.pubkey.type",
	"ssl.cert.serial", "ssl.cert.subject.cn", "ssl.chain_count",
	"ssl.cipher.bits", "ssl.cipher.name", "ssl.cipher.version", "ssl.ja3s",
	"ssl.jarm", "ssl.version", "state", "tag", "telnet.do", "telnet.dont",
	"telnet.option", "telnet.will", "telnet.wont", "uptime", "version",
	"vuln", "vuln.verified",
}

func init() {
	log.SetTimeFormat("15:04:05")
	log.SetLevel(log.DebugLevel)
}

func main() {
	defer func() {
		if r := recover(); r != nil {
			os.Exit(0)
		}
	}()

	query, facet, jsonOutput, listFacets, showHelp := parseFlags()

	if showHelp {
		displayHelp()
		return
	}

	if listFacets {
		displayFacets()
		return
	}

	results, err := searchShodan(query, facet)
	if err != nil {
		os.Exit(0)
	}

	if jsonOutput {
		json.NewEncoder(os.Stdout).Encode(results)
	} else {
		for _, item := range results {
			fmt.Println(item)
		}
	}
}

func parseFlags() (string, string, bool, bool, bool) {
	query := flag.String("q", "", "search query (required)")
	facet := flag.String("f", "ip", "facet type (use -list flag)")
	jsonOutput := flag.Bool("json", false, "stdout in JSON format")
	listFacets := flag.Bool("list", false, "list all facets")
	showHelp := flag.Bool("h", false, "show help")
	showVersion := flag.Bool("v", false, "show version")
	update := flag.Bool("up", false, "update to latest version")
	flag.Parse()

	if *showVersion {
		displayVersion()
		os.Exit(0)
	}

	if *update {
		performUpdate()
		os.Exit(0)
	}

	if *showHelp {
		return "", "", false, false, true
	}

	if *listFacets {
		return "", "", false, true, false
	}

	if *query == "" {
		displayHelp()
		os.Exit(0)
	}

	return *query, *facet, *jsonOutput, false, false
}

func displayHelp() {
	cmdStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("14"))
	argStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("8"))
	flagStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("15"))
	requiredStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("9"))
	successStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("10"))

	fmt.Println()
	fmt.Println(successStyle.Render(" example:"))
	fmt.Printf("    %s -q %s -f %s\n", cmdStyle.Render("shef"), argStyle.Render("hackerone.com"), argStyle.Render("ports"))
	fmt.Printf("    %s -q %s -json\n\n", cmdStyle.Render("shef"), argStyle.Render("apache"))

	fmt.Println(successStyle.Render(" options:"))
	fmt.Printf("    %s      search query %s\n", flagStyle.Render("-q"), requiredStyle.Render("(required)"))
	fmt.Printf("    %s      facet type %s\n", flagStyle.Render("-f"), argStyle.Render("(default: ip)"))
	fmt.Printf("    %s   stdout as JSON format\n", flagStyle.Render("-json"))
	fmt.Printf("    %s   list all facets\n", flagStyle.Render("-list"))
	fmt.Printf("    %s      show version\n", flagStyle.Render("-v"))
	fmt.Printf("    %s     update to latest version\n", flagStyle.Render("-up"))
	fmt.Printf("    %s      show this help message\n\n", flagStyle.Render("-h"))

	fmt.Println(argStyle.Render("usage of shodan for attacking targets without prior mutual consent is illegal!"))
	fmt.Println()
}

func displayVersion() {
	highlightStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("14"))
	dimStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("8"))

	fmt.Println()
	fmt.Printf("%s %s\n", highlightStyle.Render("shef"), dimStyle.Render("v"+version))
	fmt.Println()
}

func performUpdate() {
	highlightStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("14"))
	errorStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("9")).Bold(true)
	successStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("10")).Bold(true)
	dimStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("8"))

	fmt.Println()
	fmt.Println(highlightStyle.Render("checking for updates..."))

	latest, found, err := selfupdate.DetectLatest("shadowe1ite/shef")
	if err != nil {
		fmt.Printf("%s %s\n", errorStyle.Render("✗"), dimStyle.Render("error checking for updates: "+err.Error()))
		fmt.Println()
		os.Exit(1)
	}

	if !found {
		fmt.Printf("%s %s\n", errorStyle.Render("✗"), dimStyle.Render("no releases found"))
		fmt.Println()
		os.Exit(1)
	}

	currentVersion := "v" + version
	v, err := semver.ParseTolerant(strings.TrimPrefix(currentVersion, "v"))
	if err != nil {
		fmt.Printf("%s %s\n", errorStyle.Render("✗"), dimStyle.Render("invalid version format: "+err.Error()))
		fmt.Println()
		os.Exit(1)
	}

	if !latest.Version.GT(v) {
		fmt.Printf("%s %s\n", successStyle.Render("✓"), dimStyle.Render("already up to date ("+currentVersion+")"))
		fmt.Println()
		return
	}

	exe, err := os.Executable()
	if err != nil {
		fmt.Printf("%s %s\n", errorStyle.Render("✗"), dimStyle.Render("could not locate executable: "+err.Error()))
		fmt.Println()
		os.Exit(1)
	}

	fmt.Printf("  %s → %s\n", dimStyle.Render(currentVersion), highlightStyle.Render(latest.Version.String()))
	fmt.Println()
	fmt.Print(dimStyle.Render("  updating... "))

	if err := selfupdate.UpdateTo(latest.AssetURL, exe); err != nil {
		fmt.Printf("%s\n", errorStyle.Render("failed"))
		fmt.Printf("  %s\n", dimStyle.Render("error: "+err.Error()))
		fmt.Println()
		os.Exit(1)
	}

	fmt.Printf("%s\n", successStyle.Render("done"))
	fmt.Println()
	fmt.Println(dimStyle.Render("  restart shef to use the new version"))
	fmt.Println()
}

func displayFacets() {
	for _, facet := range shodanFacets {
		fmt.Println(facet)
	}
}

func searchShodan(query, facet string) ([]string, error) {
	u := fmt.Sprintf("https://www.shodan.io/search/facet?query=%s&facet=%s",
		url.QueryEscape(query), url.QueryEscape(facet))

	content, statusCode, err := fetchPage(u)
	if err != nil {
		log.Error(err.Error())
		return nil, err
	}

	if err := detectErrors(content, statusCode); err != nil {
		return nil, err
	}

	return extractResults(content)
}

// fetchProxyList fetches all 3 sources concurrently, returns whichever responds first
func fetchProxyList() []string {
	sources := []string{
		"https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt",
		"https://raw.githubusercontent.com/clarketm/proxy-list/master/proxy-list-raw.txt",
		"https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt",
	}

	ch := make(chan []string, len(sources))
	httpClient := &http.Client{Timeout: 8 * time.Second}

	for _, src := range sources {
		go func(s string) {
			resp, err := httpClient.Get(s)
			if err != nil {
				ch <- nil
				return
			}
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			var proxies []string
			for _, l := range strings.Split(strings.TrimSpace(string(body)), "\n") {
				l = strings.TrimSpace(l)
				if l != "" {
					proxies = append(proxies, "http://"+l)
				}
			}
			ch <- proxies
		}(src)
	}

	// return first non-empty result
	for i := 0; i < len(sources); i++ {
		if proxies := <-ch; len(proxies) > 0 {
			return proxies
		}
	}
	return nil
}

func doRequest(client *http.Client, targetURL string) (string, int, error) {
	req, err := http.NewRequest("GET", targetURL, nil)
	if err != nil {
		return "", 0, err
	}
	req.Header.Set("User-Agent", uarand.GetRandom())
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("Sec-Fetch-Dest", "document")
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	req.Header.Set("Sec-Fetch-Site", "none")
	req.Header.Set("Sec-Fetch-User", "?1")
	resp, err := client.Do(req)
	if err != nil {
		return "", 0, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return string(body), resp.StatusCode, nil
}

func isCloudflareBlock(body string, status int) bool {
	return (status == 403 || status == 503) &&
		(strings.Contains(body, "cloudflare") || strings.Contains(body, "Cloudflare"))
}

func fetchPage(targetURL string) (string, int, error) {
	// try direct first
	directClient := &http.Client{Timeout: 15 * time.Second}
	body, status, err := doRequest(directClient, targetURL)
	if err == nil && status == 200 {
		return body, status, nil
	}

	if err == nil && isCloudflareBlock(body, status) {
		log.Warn("Direct IP blocked by Cloudflare, trying proxies...")
	} else {
		log.Warn("Direct request failed, trying proxies...")
	}

	// fetch all proxy sources concurrently, use first that responds
	proxies := fetchProxyList()
	if len(proxies) == 0 {
		log.Error("Could not fetch proxy list")
		return "", 0, fmt.Errorf("cloudflare_block")
	}

	rand.Shuffle(len(proxies), func(i, j int) { proxies[i], proxies[j] = proxies[j], proxies[i] })

	// race proxies concurrently in batches, first success wins
	const batchSize = 20
	const proxyTimeout = 4 * time.Second

	type result struct {
		body   string
		status int
	}

	for i := 0; i < len(proxies); i += batchSize {
		end := i + batchSize
		if end > len(proxies) {
			end = len(proxies)
		}
		batch := proxies[i:end]

		ch := make(chan result, 1)
		var once sync.Once
		var wg sync.WaitGroup

		for _, p := range batch {
			wg.Add(1)
			go func(proxy string) {
				defer wg.Done()
				pURL, err := url.Parse(proxy)
				if err != nil {
					return
				}
				c := &http.Client{
					Transport: &http.Transport{Proxy: http.ProxyURL(pURL)},
					Timeout:   proxyTimeout,
				}
				b, s, err := doRequest(c, targetURL)
				if err != nil || isCloudflareBlock(b, s) || s != 200 {
					return
				}
				once.Do(func() { ch <- result{b, s} })
			}(p)
		}

		go func() { wg.Wait(); close(ch) }()

		if res, ok := <-ch; ok {
			return res.body, res.status, nil
		}
	}

	return "", 0, fmt.Errorf("cloudflare_block")
}

func detectErrors(html string, statusCode int) error {
	if statusCode == 403 || statusCode == 503 {
		if strings.Contains(html, "cloudflare") || strings.Contains(html, "Cloudflare") {
			log.Warn("Request blocked by Cloudflare", "advice", "Try again later or use a different IP")
			return fmt.Errorf("cloudflare_block")
		}
	}

	if statusCode != 200 {
		return fmt.Errorf("HTTP error %d", statusCode)
	}

	doc, err := goquery.NewDocumentFromReader(strings.NewReader(html))
	if err != nil {
		log.Error("Failed to parse HTML")
		return err
	}

	if notice := doc.Find(".alert-notice"); notice.Length() > 0 {
		msg := cleanMessage(notice.Text())
		log.Info(msg)
		return fmt.Errorf("shodan_notice")
	}

	if alert := doc.Find(".alert-error"); alert.Length() > 0 {
		msg := cleanMessage(alert.Text())
		log.Error(msg)
		return fmt.Errorf("shodan_error")
	}

	if strings.Contains(html, "The search request has timed out") {
		log.Error("Search request timed out")
		return fmt.Errorf("timeout_error")
	}

	if strings.Contains(html, "wildcard searches are not supported") {
		log.Error("Wildcard searches are not supported")
		return fmt.Errorf("wildcard_error")
	}

	return nil
}

func cleanMessage(msg string) string {
	msg = strings.TrimSpace(msg)
	msg = strings.ReplaceAll(msg, "\n", " ")
	msg = strings.ReplaceAll(msg, "  ", " ")
	msg = strings.TrimPrefix(msg, "Error:")
	msg = strings.TrimPrefix(msg, "Note:")
	return strings.TrimSpace(msg)
}

func extractResults(html string) ([]string, error) {
	doc, err := goquery.NewDocumentFromReader(strings.NewReader(html))
	if err != nil {
		log.Error("Failed to parse results")
		return nil, err
	}

	results := []string{}
	doc.Find(".facet-row .name strong").Each(func(i int, s *goquery.Selection) {
		value := strings.TrimSpace(s.Text())
		if value != "" {
			results = append(results, value)
		}
	})

	if len(results) == 0 {
		log.Error("No results found")
		return nil, fmt.Errorf("no_results")
	}

	return results, nil
}

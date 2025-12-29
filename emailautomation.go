package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"io"
	"mime"
	"mime/quotedprintable"
	"net/smtp"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/rix4uni/emailautomation/banner"
	"github.com/spf13/pflag"

	"github.com/PuerkitoBio/goquery"
	"github.com/alecthomas/chroma"
	chromahtml "github.com/alecthomas/chroma/formatters/html"
	"github.com/alecthomas/chroma/lexers"
	"github.com/alecthomas/chroma/styles"
	"github.com/vanng822/go-premailer/premailer"
	"github.com/yuin/goldmark"
	"github.com/yuin/goldmark/extension"
	"github.com/yuin/goldmark/parser"
	"github.com/yuin/goldmark/renderer"
	"gopkg.in/yaml.v3"
)

// Config represents the entire config file structure
type Config struct {
	Credentials []Credential `yaml:"credentials"`
}

// Credential represents a single credential entry
type Credential struct {
	ID           string `yaml:"id"`
	Email        string `yaml:"email"`
	AppPassword  string `yaml:"app_password"`
	SMTPHost     string `yaml:"smtp_host"`
	SMTPPort     string `yaml:"smtp_port"`
	Subject      string `yaml:"subject"`
	SMTPUsername string `yaml:"smtp_username,omitempty"` // Optional: for AWS SES SMTP, defaults to email if not provided
}

var noMarkdown = pflag.Bool("nomarkdown", false, "Send email as plain text instead of HTML")
var debugEmail = pflag.Bool("debug", false, "Write email message to email_debug.txt for debugging")
var markdownFile = pflag.String("markdown-file", "mdfile", "Path to a single .md file or directory containing .md files")
var configID = pflag.String("id", "1", "Credential ID to use from config.yaml")
var domainFilter = pflag.Bool("domain-filter", false, "Filter emails to only include those matching the base domain from the markdown file")
var delaySeconds = pflag.Int("delay", 300, "Delay in seconds between email sends (default: 300 for Gmail's 500/day limit)")
var silent = pflag.Bool("silent", false, "Silent mode.")
var version = pflag.Bool("version", false, "Print the version of the tool and exit.")
var emailVerify = pflag.Bool("emailverify", false, "Only send to recipients where emailverify checked_count == 3")

// Embedded CSS from Markdown Here
const defaultCSS = `/* This is the overall wrapper, it should be treated as the body section. */
.markdown-here-wrapper {
}

pre, code {
  font-size: 0.85em;
  font-family: Consolas, Inconsolata, Courier, monospace;
}

code {
  margin: 0 0.15em;
  padding: 0 0.3em;
  white-space: pre-wrap;
  border: 1px solid #EAEAEA;
  background-color: #F8F8F8;
  border-radius: 3px;
  display: inline;
}

pre {
  font-size: 1em;
  line-height: 1.2em;
}

pre code {
  white-space: pre;
  overflow: auto;
  border-radius: 3px;
  border: 1px solid #CCC;
  padding: 0.5em 0.7em;
  display: block !important;
}

p {
  margin: 0 0 1.2em 0 !important;
}

table, pre, dl, blockquote, q, ul, ol {
  margin: 1.2em 0;
}

ul, ol {
  padding-left: 2em;
}

li {
  margin: 0.5em 0;
}

li p {
  margin: 0.5em 0 !important;
}

ul ul, ul ol, ol ul, ol ol {
  margin: 0;
  padding-left: 1em;
}

ol ol, ul ol {
  list-style-type: lower-roman;
}

ul ul ol, ul ol ol, ol ul ol, ol ol ol {
  list-style-type: lower-alpha;
}

dl {
  padding: 0;
}

dl dt {
  font-size: 1em;
  font-weight: bold;
  font-style: italic;
}

dl dd {
  margin: 0 0 1em;
  padding: 0 1em;
}

blockquote, q {
  border-left: 4px solid #DDD;
  padding: 0 1em;
  color: #777;
  quotes: none;
}

blockquote::before, blockquote::after, q::before, q::after {
  content: none;
}

h1, h2, h3, h4, h5, h6 {
  margin: 1.3em 0 1em;
  padding: 0;
  font-weight: bold;
}

h1 {
  font-size: 1.6em;
  border-bottom: 1px solid #ddd;
}

h2 {
  font-size: 1.4em;
  border-bottom: 1px solid #eee;
}

h3 {
  font-size: 1.3em;
}

h4 {
  font-size: 1.2em;
}

h5 {
  font-size: 1em;
}

h6 {
  font-size: 1em;
  color: #777;
}

table {
  padding: 0;
  border-collapse: collapse;
  border-spacing: 0;
  font-size: 1em;
  font: inherit;
  border: 0;
}

tbody {
  margin: 0;
  padding: 0;
  border: 0;
}

table tr {
  border: 0;
  border-top: 1px solid #CCC;
  background-color: white;
  margin: 0;
  padding: 0;
}

table tr:nth-child(2n) {
  background-color: #F8F8F8;
}

table tr th, table tr td {
  font-size: 1em;
  border: 1px solid #CCC;
  margin: 0;
  padding: 0.5em 1em;
}

table tr th {
  font-weight: bold;
  background-color: #F0F0F0;
}`

const githubCSS = `pre code.hljs {
  display: block;
  overflow-x: auto;
  padding: 1em;
}

code.hljs {
  padding: 3px 5px;
}

.hljs {
  color: #24292e;
  background: #ffffff;
}

.hljs-doctag,
.hljs-keyword,
.hljs-meta .hljs-keyword,
.hljs-template-tag,
.hljs-template-variable,
.hljs-type,
.hljs-variable.language_ {
  color: #d73a49;
}

.hljs-title,
.hljs-title.class_,
.hljs-title.class_.inherited__,
.hljs-title.function_ {
  color: #6f42c1;
}

.hljs-attr,
.hljs-attribute,
.hljs-literal,
.hljs-meta,
.hljs-number,
.hljs-operator,
.hljs-variable,
.hljs-selector-attr,
.hljs-selector-class,
.hljs-selector-id {
  color: #005cc5;
}

.hljs-regexp,
.hljs-string,
.hljs-meta .hljs-string {
  color: #032f62;
}

.hljs-built_in,
.hljs-symbol {
  color: #e36209;
}

.hljs-comment,
.hljs-code,
.hljs-formula {
  color: #6a737d;
}

.hljs-name,
.hljs-quote,
.hljs-selector-tag,
.hljs-selector-pseudo {
  color: #22863a;
}

.hljs-subst {
  color: #24292e;
}

.hljs-section {
  color: #005cc5;
  font-weight: bold;
}

.hljs-bullet {
  color: #735c0f;
}

.hljs-emphasis {
  color: #24292e;
  font-style: italic;
}

.hljs-strong {
  color: #24292e;
  font-weight: bold;
}

.hljs-addition {
  color: #22863a;
  background-color: #f0fff4;
}

.hljs-deletion {
  color: #b31d28;
	background-color: #ffeef0;
}`

// generateMessageID generates a unique message ID for the email
func generateMessageID(from string) string {
	// Extract domain from email
	parts := strings.Split(from, "@")
	domain := "localhost"
	if len(parts) > 1 {
		domain = parts[1]
	}

	// Generate random bytes
	randomBytes := make([]byte, 16)
	rand.Read(randomBytes)
	randomStr := base64.URLEncoding.EncodeToString(randomBytes)

	// Format: <timestamp.random@domain>
	timestamp := time.Now().UnixNano()
	return fmt.Sprintf("<%d.%s@%s>", timestamp, randomStr, domain)
}

// encodeSubject encodes subject line with non-ASCII characters using MIME encoding
func encodeSubject(subject string) string {
	// Check if subject contains non-ASCII characters
	hasNonASCII := false
	for _, r := range subject {
		if r > 127 {
			hasNonASCII = true
			break
		}
	}

	if !hasNonASCII {
		return subject
	}

	// Use MIME encoding for non-ASCII characters
	return mime.QEncoding.Encode("UTF-8", subject)
}

// htmlToPlainText converts HTML to plain text by stripping tags and formatting
func htmlToPlainText(html string) string {
	doc, err := goquery.NewDocumentFromReader(strings.NewReader(html))
	if err != nil {
		// Fallback: simple regex-based stripping
		re := regexp.MustCompile(`<[^>]*>`)
		text := re.ReplaceAllString(html, "")
		text = strings.ReplaceAll(text, "&nbsp;", " ")
		text = strings.ReplaceAll(text, "&amp;", "&")
		text = strings.ReplaceAll(text, "&lt;", "<")
		text = strings.ReplaceAll(text, "&gt;", ">")
		text = strings.ReplaceAll(text, "&quot;", "\"")
		text = strings.ReplaceAll(text, "&#39;", "'")
		return strings.TrimSpace(text)
	}

	// Extract text content
	var text strings.Builder
	doc.Find("body, .markdown-here-wrapper").Each(func(i int, s *goquery.Selection) {
		text.WriteString(s.Text())
		text.WriteString("\n")
	})

	result := text.String()
	if result == "" {
		// Fallback to all text
		result = doc.Text()
	}

	// Clean up whitespace
	lines := strings.Split(result, "\n")
	var cleanedLines []string
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed != "" {
			cleanedLines = append(cleanedLines, trimmed)
		}
	}

	return strings.Join(cleanedLines, "\n")
}

// encodeQuotedPrintable encodes text using quoted-printable encoding
func encodeQuotedPrintable(text string) (string, error) {
	var buf bytes.Buffer
	w := quotedprintable.NewWriter(&buf)
	_, err := w.Write([]byte(text))
	if err != nil {
		return "", err
	}
	err = w.Close()
	if err != nil {
		return "", err
	}
	return buf.String(), nil
}

// foldHeader folds long email headers according to RFC 5322
// Headers should be folded at 78 characters with continuation lines starting with space
func foldHeader(name, value string) string {
	// RFC 5322: Headers should be folded at 78 characters (recommended limit)
	// Continuation lines start with space or tab
	const maxLineLength = 78

	// Calculate header name length + ": " = name length + 2
	headerPrefixLen := len(name) + 2

	// If the entire header fits on one line, return it as-is
	if headerPrefixLen+len(value) <= maxLineLength {
		return fmt.Sprintf("%s: %s\r\n", name, value)
	}

	// Fold the header
	var result strings.Builder
	result.WriteString(fmt.Sprintf("%s: ", name))
	currentLineLen := headerPrefixLen

	// Split by comma for email lists (To, Cc, Bcc), or by space for other headers
	if name == "To" || name == "Cc" || name == "Bcc" {
		// For email lists, split by comma and space
		emails := strings.Split(value, ", ")
		for i, email := range emails {
			// Calculate what we need to add (comma + space + email for non-first)
			separator := ""
			if i > 0 {
				separator = ", "
			}
			toAdd := separator + email

			// Check if we need to fold
			if currentLineLen+len(toAdd) > maxLineLength && currentLineLen > headerPrefixLen {
				// Start new continuation line (starts with space)
				result.WriteString("\r\n ")
				currentLineLen = 1 // Space at start of continuation line
				// On continuation line, add comma+space+email
				if i > 0 {
					result.WriteString(", ")
					currentLineLen += 2
				}
			} else if i > 0 {
				// Add comma and space on same line
				result.WriteString(", ")
				currentLineLen += 2
			}

			result.WriteString(email)
			currentLineLen += len(email)
		}
	} else {
		// For other headers, fold at word boundaries
		words := strings.Fields(value)
		for i, word := range words {
			// Check if we need to fold
			wordWithSpace := word
			if i > 0 {
				wordWithSpace = " " + word
			}

			if currentLineLen+len(wordWithSpace) > maxLineLength && currentLineLen > headerPrefixLen {
				// Start new continuation line
				result.WriteString("\r\n ")
				currentLineLen = 1
				result.WriteString(word)
				currentLineLen += len(word)
			} else {
				if i > 0 {
					result.WriteString(" ")
					currentLineLen++
				}
				result.WriteString(word)
				currentLineLen += len(word)
			}
		}
	}

	result.WriteString("\r\n")
	return result.String()
}

// addEmailHeaders generates all required email headers
func addEmailHeaders(from string, to []string, subject, replyTo string) string {
	var headers strings.Builder

	// From
	headers.WriteString(foldHeader("From", from))

	// To (comma-separated list of all recipients, properly folded)
	toHeader := strings.Join(to, ", ")
	headers.WriteString(foldHeader("To", toHeader))

	// Subject (encoded if needed, then folded)
	subjectEncoded := encodeSubject(subject)
	headers.WriteString(foldHeader("Subject", subjectEncoded))

	// Date (RFC 5322 format, folded if needed)
	now := time.Now()
	headers.WriteString(foldHeader("Date", now.Format(time.RFC1123Z)))

	// Message-ID (folded if needed)
	messageID := generateMessageID(from)
	headers.WriteString(foldHeader("Message-ID", messageID))

	// Reply-To (default to from if not specified)
	if replyTo == "" {
		replyTo = from
	}
	headers.WriteString(foldHeader("Reply-To", replyTo))

	// X-Mailer (folded if needed)
	headers.WriteString(foldHeader("X-Mailer", "EmailAutomation/1.0"))

	// MIME-Version
	headers.WriteString("MIME-Version: 1.0\r\n")

	return headers.String()
}

// generateBoundary generates an RFC-compliant MIME boundary using only safe characters
func generateBoundary() string {
	randomBytes := make([]byte, 12)
	rand.Read(randomBytes)
	// Create boundary with only safe alphanumeric characters
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	boundary := "----=_NextPart_"
	for _, b := range randomBytes {
		boundary += string(charset[b%byte(len(charset))])
	}
	// Add timestamp for additional uniqueness
	boundary += fmt.Sprintf("_%d", time.Now().UnixNano())
	return boundary
}

// writeDebugEmail writes the email message to a file for debugging
func writeDebugEmail(message string) {
	if *debugEmail {
		err := os.WriteFile("email_debug.txt", []byte(message), 0644)
		if err == nil {
			fmt.Println("Debug: Email message written to email_debug.txt")
		} else {
			fmt.Printf("Debug: Failed to write email_debug.txt: %v\n", err)
		}
	}
}

// createMultipartEmail creates a multipart/alternative email with both plain text and HTML
// Returns the email body and the boundary used
func createMultipartEmail(plainText, html string) (string, string, error) {
	// Generate RFC-compliant boundary
	boundary := generateBoundary()

	var body strings.Builder

	// Plain text part
	body.WriteString(fmt.Sprintf("--%s\r\n", boundary))
	body.WriteString("Content-Type: text/plain; charset=UTF-8\r\n")
	body.WriteString("Content-Transfer-Encoding: quoted-printable\r\n")
	body.WriteString("\r\n")

	plainTextEncoded, err := encodeQuotedPrintable(plainText)
	if err != nil {
		return "", boundary, fmt.Errorf("failed to encode plain text: %w", err)
	}
	body.WriteString(plainTextEncoded)
	body.WriteString("\r\n")

	// HTML part
	body.WriteString(fmt.Sprintf("--%s\r\n", boundary))
	body.WriteString("Content-Type: text/html; charset=UTF-8\r\n")
	body.WriteString("Content-Transfer-Encoding: quoted-printable\r\n")
	body.WriteString("\r\n")

	htmlEncoded, err := encodeQuotedPrintable(html)
	if err != nil {
		return "", boundary, fmt.Errorf("failed to encode HTML: %w", err)
	}
	body.WriteString(htmlEncoded)
	body.WriteString("\r\n")

	// End boundary
	body.WriteString(fmt.Sprintf("--%s--\r\n", boundary))

	return body.String(), boundary, nil
}

// extractDomainFromMarkdown extracts the domain from the Target section in markdown file
func extractDomainFromMarkdown(filePath string) (string, error) {
	// Read markdown file
	content, err := os.ReadFile(filePath)
	if err != nil {
		return "", fmt.Errorf("failed to read file: %w", err)
	}

	// Find "## Target" section
	lines := strings.Split(string(content), "\n")
	inTargetSection := false
	inCodeBlock := false

	for _, line := range lines {
		if strings.HasPrefix(line, "## Target") {
			inTargetSection = true
			continue
		}

		if inTargetSection {
			if strings.HasPrefix(line, "```") {
				inCodeBlock = !inCodeBlock
				continue
			}

			if inCodeBlock {
				// Extract URL from code block
				urlPattern := regexp.MustCompile(`https?://([^/\s]+)`)
				matches := urlPattern.FindStringSubmatch(line)
				if len(matches) >= 2 {
					return matches[1], nil
				}
			}

			// Stop if we've moved to next section
			if strings.HasPrefix(line, "## ") && !strings.HasPrefix(line, "## Target") {
				break
			}
		}
	}

	return "", fmt.Errorf("could not find domain in Target section")
}

// extractURLFromMarkdown extracts the full URL from the Target section
func extractURLFromMarkdown(filePath string) (string, error) {
	content, err := os.ReadFile(filePath)
	if err != nil {
		return "", fmt.Errorf("failed to read file: %w", err)
	}

	lines := strings.Split(string(content), "\n")
	inTargetSection := false
	inCodeBlock := false

	for _, line := range lines {
		if strings.HasPrefix(line, "## Target") {
			inTargetSection = true
			continue
		}

		if inTargetSection {
			if strings.HasPrefix(line, "```") {
				inCodeBlock = !inCodeBlock
				continue
			}

			if inCodeBlock {
				line = strings.TrimSpace(line)
				if strings.HasPrefix(line, "http://") || strings.HasPrefix(line, "https://") {
					return line, nil
				}
			}

			// Stop if we've moved to next section
			if strings.HasPrefix(line, "## ") && !strings.HasPrefix(line, "## Target") {
				break
			}
		}
	}

	return "", fmt.Errorf("URL not found in Target section")
}

// extractBaseDomain extracts the base domain using tldinfo command
// Example: "https://doapp.nnsp.tech" -> "nnsp.tech"
func extractBaseDomain(url string) (string, error) {
	// Execute: echo "https://doapp.nnsp.tech" | tldinfo --silent --extract domain,suffix
	cmd := exec.Command("sh", "-c", fmt.Sprintf("echo \"%s\" | tldinfo --silent --extract domain,suffix", url))
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("failed to extract base domain: %w", err)
	}

	baseDomain := strings.TrimSpace(string(output))
	baseDomain = strings.TrimSpace(stripANSI(baseDomain)) // Remove ANSI codes if any

	if baseDomain == "" {
		return "", fmt.Errorf("empty base domain extracted")
	}

	return baseDomain, nil
}

// filterEmailsByDomain filters emails to only include those matching the base domain
func filterEmailsByDomain(emails []string, baseDomain string) []string {
	var filtered []string
	baseDomainLower := strings.ToLower(baseDomain)

	for _, email := range emails {
		// Extract domain from email (part after @)
		parts := strings.Split(email, "@")
		if len(parts) != 2 {
			continue // Invalid email format, skip
		}

		emailDomain := strings.ToLower(strings.TrimSpace(parts[1]))

		// Check if email domain matches base domain
		if emailDomain == baseDomainLower {
			filtered = append(filtered, email)
		}
	}

	return filtered
}

type emailVerifyResult struct {
	CheckedCount int `json:"checked_count"`
}

// runEmailVerify executes `emailverify --silent --json` for a single email and returns checked_count.
func runEmailVerify(email string) (int, error) {
	// Execute: echo "user@example.com" | emailverify --silent --json
	cmd := exec.Command("sh", "-c", fmt.Sprintf("echo %q | emailverify --silent --json", email))
	output, err := cmd.Output()
	if err != nil {
		return 0, fmt.Errorf("emailverify failed: %w", err)
	}

	outStr := strings.TrimSpace(stripANSI(string(output)))
	if outStr == "" {
		return 0, fmt.Errorf("emailverify returned empty output")
	}

	var res emailVerifyResult
	if err := json.Unmarshal([]byte(outStr), &res); err != nil {
		return 0, fmt.Errorf("failed to parse emailverify JSON: %w", err)
	}

	return res.CheckedCount, nil
}

// filterRecipientsByEmailVerify keeps only emails where emailverify checked_count == 3.
// If emailverify fails or output can't be parsed, the email is treated as not verified (skipped).
func filterRecipientsByEmailVerify(recipients []string) ([]string, error) {
	filtered := make([]string, 0, len(recipients))
	for _, r := range recipients {
		checked, err := runEmailVerify(r)
		if err != nil {
			if !*silent {
				fmt.Printf("Warning: emailverify failed for %s: %v\n", r, err)
			}
			continue
		}
		if checked == 3 {
			filtered = append(filtered, r)
		}
	}
	return filtered, nil
}

// stripANSI removes ANSI escape sequences from a string
func stripANSI(s string) string {
	// Match ANSI escape sequences: \x1b[ or \033[ followed by numbers and ending with m
	ansiRegex := regexp.MustCompile(`\x1b\[[0-9;]*m|\033\[[0-9;]*m`)
	return ansiRegex.ReplaceAllString(s, "")
}

// extractEmailsFromDomain extracts emails from domain and subdomains using emailextractor
func extractEmailsFromDomain(domain string) ([]string, error) {
	emailMap := make(map[string]bool)
	currentDomain := domain

	// While domain has dots (more than one part)
	for strings.Contains(currentDomain, ".") {
		// Execute: echo "https://$domain" | emailextractor -silent
		cmd := exec.Command("sh", "-c", fmt.Sprintf("echo \"https://%s\" | emailextractor -silent", currentDomain))
		output, err := cmd.Output()
		if err == nil {
			// Parse output for lines with "::"
			lines := strings.Split(string(output), "\n")
			for _, line := range lines {
				if strings.Contains(line, "::") {
					// Extract email (everything after ":: ")
					parts := strings.Split(line, ":: ")
					if len(parts) >= 2 {
						// Strip ANSI escape codes before processing
						email := strings.TrimSpace(stripANSI(parts[1]))
						if email != "" && strings.Contains(email, "@") {
							emailMap[email] = true
						}
					}
				}
			}
		}

		// Remove leftmost subdomain: domain="${domain#*.}"
		if idx := strings.Index(currentDomain, "."); idx != -1 {
			currentDomain = currentDomain[idx+1:]
		} else {
			break
		}
	}

	// Convert map to sorted slice
	emails := make([]string, 0, len(emailMap))
	for email := range emailMap {
		emails = append(emails, email)
	}
	sort.Strings(emails)

	return emails, nil
}

// handleSkippedEmail creates skippedemails directory and copies the markdown file there.
// It adds a unique suffix to avoid filename collisions.
func handleSkippedEmail(mdFilePath string, reason string) error {
	const skippedDir = "skippedemails"

	if err := os.MkdirAll(skippedDir, 0755); err != nil {
		return fmt.Errorf("failed to create %s directory: %w", skippedDir, err)
	}

	base := filepath.Base(mdFilePath)
	ext := filepath.Ext(base)
	name := strings.TrimSuffix(base, ext)
	ts := time.Now().Format("20060102-150405")

	// Base destination name: <name>__<reason>__<timestamp>.md
	destBase := fmt.Sprintf("%s__%s__%s%s", name, reason, ts, ext)
	destPath := filepath.Join(skippedDir, destBase)

	// If collision, add counter suffix.
	for i := 1; ; i++ {
		if _, err := os.Stat(destPath); os.IsNotExist(err) {
			break
		}
		destBase = fmt.Sprintf("%s__%s__%s__%d%s", name, reason, ts, i, ext)
		destPath = filepath.Join(skippedDir, destBase)
	}

	src, err := os.Open(mdFilePath)
	if err != nil {
		return fmt.Errorf("failed to open source file: %w", err)
	}
	defer src.Close()

	dst, err := os.Create(destPath)
	if err != nil {
		return fmt.Errorf("failed to create destination file: %w", err)
	}
	defer dst.Close()

	if _, err := io.Copy(dst, src); err != nil {
		return fmt.Errorf("failed to copy file: %w", err)
	}

	fmt.Printf("Copied %s to %s\n", mdFilePath, destPath)
	return nil
}

// loadConfig reads and parses config.yaml from multiple locations
// Priority: 1) ~/.config/emailautomation/config.yaml, 2) ./config.yaml
func loadConfig() (*Config, error) {
	var configPaths []string

	// Get home directory
	homeDir, err := os.UserHomeDir()
	if err == nil {
		// First priority: ~/.config/emailautomation/config.yaml
		configPath := filepath.Join(homeDir, ".config", "emailautomation", "config.yaml")
		configPaths = append(configPaths, configPath)
	}

	// Second priority: current directory
	configPaths = append(configPaths, "config.yaml")

	// Try each path in order
	for _, configPath := range configPaths {
		content, err := os.ReadFile(configPath)
		if err == nil {
			// File found, parse it
			var config Config
			err = yaml.Unmarshal(content, &config)
			if err != nil {
				return nil, fmt.Errorf("failed to parse config.yaml at %s: %w", configPath, err)
			}
			return &config, nil
		}
	}

	// Neither file exists
	return nil, fmt.Errorf("config.yaml not found in any location. Checked: %v", configPaths)
}

// getCredentialByID finds a credential by ID
func getCredentialByID(config *Config, id string) (*Credential, error) {
	for _, cred := range config.Credentials {
		if cred.ID == id {
			return &cred, nil
		}
	}
	return nil, fmt.Errorf("credential with ID '%s' not found in config.yaml", id)
}

const sentEmailsLogFile = "sent_emails.log"

// isCredentialError checks if the error is an SMTP authentication/credential error
func isCredentialError(err error) bool {
	if err == nil {
		return false
	}
	errStr := err.Error()
	// Check for Gmail's specific error codes and messages
	return strings.Contains(errStr, "535 5.7.8") ||
		strings.Contains(errStr, "Username and Password not accepted") ||
		strings.Contains(errStr, "BadCredentials") ||
		strings.Contains(errStr, "535")
}

// calculateFileHash calculates SHA256 hash of file content
func calculateFileHash(filePath string) (string, error) {
	content, err := os.ReadFile(filePath)
	if err != nil {
		return "", err
	}
	hash := sha256.Sum256(content)
	return hex.EncodeToString(hash[:]), nil
}

// loadSentEmails reads the log file and returns a map of file path -> hash
// Format: filepath|hash (one per line)
func loadSentEmails() (map[string]string, error) {
	sentMap := make(map[string]string)

	if _, err := os.Stat(sentEmailsLogFile); os.IsNotExist(err) {
		return sentMap, nil // File doesn't exist yet, return empty map
	}

	content, err := os.ReadFile(sentEmailsLogFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read log file: %w", err)
	}

	lines := strings.Split(string(content), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.Split(line, "|")
		if len(parts) == 2 {
			sentMap[parts[0]] = parts[1]
		}
	}

	return sentMap, nil
}

// markAsSent appends a file path and hash to the log file
func markAsSent(filePath string, hash string) error {
	logEntry := fmt.Sprintf("%s|%s\n", filePath, hash)
	f, err := os.OpenFile(sentEmailsLogFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("failed to open log file: %w", err)
	}
	defer f.Close()

	_, err = f.WriteString(logEntry)
	if err != nil {
		return fmt.Errorf("failed to write to log file: %w", err)
	}

	return nil
}

// isAlreadySent checks if a file (with its current hash) has already been sent
func isAlreadySent(filePath string, currentHash string, sentMap map[string]string) bool {
	storedHash, exists := sentMap[filePath]
	return exists && storedHash == currentHash
}

// getMarkdownFiles returns a list of .md file paths
// If input is a .md file, returns single file
// If input is a directory, returns all .md files in that directory
func getMarkdownFiles(inputPath string) ([]string, error) {
	// Check if it's a .md file
	if strings.HasSuffix(strings.ToLower(inputPath), ".md") {
		if _, err := os.Stat(inputPath); err == nil {
			return []string{inputPath}, nil
		}
		return nil, fmt.Errorf("file not found: %s", inputPath)
	}

	// Treat as directory
	var files []string
	err := filepath.Walk(inputPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && strings.HasSuffix(strings.ToLower(path), ".md") {
			files = append(files, path)
		}
		return nil
	})
	return files, err
}

// processMarkdownFile processes a single markdown file:
// 1. Extracts domain from the file
// 2. Finds email recipients for that domain
// 3. Sends email if recipients found, otherwise copies file to skippedemails
// Returns: (emailSent bool, error)
func processMarkdownFile(mdFilePath string, from, subject, appPassword, smtpHost, smtpPort, smtpUsername string, useMarkdown bool, writeDebug bool, sentMap map[string]string) (bool, error) {
	// Calculate file hash
	fileHash, err := calculateFileHash(mdFilePath)
	if err != nil {
		return false, fmt.Errorf("failed to calculate file hash: %w", err)
	}

	// Check if already sent
	if isAlreadySent(mdFilePath, fileHash, sentMap) {
		fmt.Printf("[%s] Already sent (skipping)\n", filepath.Base(mdFilePath))
		return false, nil
	}

	// Read email body
	body, err := os.ReadFile(mdFilePath)
	if err != nil {
		return false, fmt.Errorf("error reading %s: %w", mdFilePath, err)
	}

	// Extract domain
	domain, err := extractDomainFromMarkdown(mdFilePath)
	if err != nil {
		fmt.Printf("Error extracting domain from %s: %v\n", mdFilePath, err)
		return false, err
	}

	// Extract emails from domain
	recipients, err := extractEmailsFromDomain(domain)
	if err != nil || len(recipients) == 0 {
		fmt.Printf("No emails found for %s, copying file to skippedemails directory\n", mdFilePath)
		if err := handleSkippedEmail(mdFilePath, "no_emails_found"); err != nil {
			return false, fmt.Errorf("error handling skipped email: %w", err)
		}
		return false, nil // No email sent, no error
	}

	// Apply domain filter if flag is enabled
	if *domainFilter {
		// Get the full URL from markdown to extract base domain
		url, err := extractURLFromMarkdown(mdFilePath)
		if err != nil {
			return false, fmt.Errorf("failed to extract URL for domain filtering: %w", err)
		}

		// Extract base domain using tldinfo
		baseDomain, err := extractBaseDomain(url)
		if err != nil {
			return false, fmt.Errorf("failed to extract base domain: %w", err)
		}

		fmt.Printf("[%s] Filtering emails by base domain: %s\n", filepath.Base(mdFilePath), baseDomain)

		// Filter emails
		originalCount := len(recipients)
		recipients = filterEmailsByDomain(recipients, baseDomain)

		if len(recipients) == 0 {
			fmt.Printf("[%s] No emails match base domain %s (filtered from %d email(s)), skipping send\n",
				filepath.Base(mdFilePath), baseDomain, originalCount)
			if err := handleSkippedEmail(mdFilePath, "domain_filter_no_match"); err != nil {
				return false, fmt.Errorf("error handling skipped email: %w", err)
			}
			return false, nil // No email sent, no error
		}

		fmt.Printf("[%s] Filtered to %d matching email(s) (from %d total)\n",
			filepath.Base(mdFilePath), len(recipients), originalCount)
	}

	// Apply emailverify filter if flag is enabled
	if *emailVerify {
		originalCount := len(recipients)
		filtered, _ := filterRecipientsByEmailVerify(recipients)
		recipients = filtered

		if len(recipients) == 0 {
			fmt.Printf("[%s] No emails passed emailverify (checked_count == 3) (filtered from %d email(s)), skipping send\n",
				filepath.Base(mdFilePath), originalCount)
			if err := handleSkippedEmail(mdFilePath, "emailverify_no_match"); err != nil {
				return false, fmt.Errorf("error handling skipped email: %w", err)
			}
			return false, nil // No email sent, no error
		}

		fmt.Printf("[%s] Emailverify kept %d email(s) (from %d total)\n",
			filepath.Base(mdFilePath), len(recipients), originalCount)
	}

	fmt.Printf("[%s] Found %d email(s), sending one email to all recipients...\n", filepath.Base(mdFilePath), len(recipients))

	// SMTP authentication
	// Use smtp_username if provided (for AWS SES), otherwise use email address (for Gmail)
	identity := from
	if smtpUsername != "" {
		identity = smtpUsername
	}
	auth := smtp.PlainAuth("", identity, appPassword, smtpHost)
	addr := smtpHost + ":" + smtpPort

	// Compose and send email
	message := composeEmail(from, recipients, subject, string(body), useMarkdown)

	// Write debug output if requested (only for first file to avoid overwriting)
	if writeDebug && *debugEmail {
		writeDebugEmail(message)
	}

	err = smtp.SendMail(addr, auth, from, recipients, []byte(message))
	if err != nil {
		// Check if it's a credential error
		if isCredentialError(err) {
			return false, fmt.Errorf("invalid credentials in config.yaml: %w", err)
		}
		return false, fmt.Errorf("error sending email for %s: %w", mdFilePath, err)
	}

	if useMarkdown {
		fmt.Printf("[%s] Email sent successfully as HTML to %d recipient(s): %s\n",
			filepath.Base(mdFilePath), len(recipients), strings.Join(recipients, ", "))
	} else {
		fmt.Printf("[%s] Email sent successfully as plain text to %d recipient(s): %s\n",
			filepath.Base(mdFilePath), len(recipients), strings.Join(recipients, ", "))
	}

	// Mark as sent
	if err := markAsSent(mdFilePath, fileHash); err != nil {
		fmt.Printf("Warning: Failed to log sent email: %v\n", err)
		// Don't fail the whole operation if logging fails
	}

	return true, nil // Email was sent successfully
}

func main() {
	pflag.Parse()

	// Print version and exit if -version flag is provided
	if *version {
		banner.PrintBanner()
		banner.PrintVersion()
		return
	}

	// Don't Print banner if -silent flag is provided
	if !*silent {
		banner.PrintBanner()
	}

	// Load configuration
	config, err := loadConfig()
	if err != nil {
		fmt.Printf("Error loading config: %v\n", err)
		os.Exit(1)
	}

	// Get credential by ID
	cred, err := getCredentialByID(config, *configID)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		fmt.Printf("Available credential IDs: ")
		for i, c := range config.Credentials {
			if i > 0 {
				fmt.Print(", ")
			}
			fmt.Print(c.ID)
		}
		fmt.Println()
		os.Exit(1)
	}

	// Use credentials from config
	from := cred.Email
	subject := cred.Subject
	appPassword := cred.AppPassword
	smtpHost := cred.SMTPHost
	smtpPort := cred.SMTPPort
	smtpUsername := cred.SMTPUsername

	useMarkdown := !*noMarkdown

	// Load sent emails log
	sentMap, err := loadSentEmails()
	if err != nil {
		fmt.Printf("Warning: Failed to load sent emails log: %v\n", err)
		sentMap = make(map[string]string) // Continue with empty map
	}

	// Get list of markdown files to process
	mdFiles, err := getMarkdownFiles(*markdownFile)
	if err != nil {
		fmt.Printf("Error getting markdown files: %v\n", err)
		os.Exit(1)
	}

	if len(mdFiles) == 0 {
		fmt.Printf("No .md files found in %s\n", *markdownFile)
		os.Exit(0)
	}

	fmt.Printf("Processing %d markdown file(s)...\n\n", len(mdFiles))

	// Process each file
	successCount := 0
	errorCount := 0
	for i, mdFilePath := range mdFiles {
		fmt.Printf("--- Processing file %d/%d: %s ---\n", i+1, len(mdFiles), filepath.Base(mdFilePath))

		emailSent, err := processMarkdownFile(mdFilePath, from, subject, appPassword, smtpHost, smtpPort, smtpUsername, useMarkdown, i == 0, sentMap)
		if err != nil {
			// Check if it's a credential error - exit immediately
			if isCredentialError(err) {
				fmt.Printf("Fatal error: %v\n", err)
				fmt.Println("Please check your credentials in config.yaml and ensure they are correct.")
				os.Exit(1)
			}
			errorCount++
			fmt.Printf("Error processing %s: %v\n\n", mdFilePath, err)
		} else {
			successCount++
			// Update in-memory map after successful send (for efficiency in same run)
			fileHash, hashErr := calculateFileHash(mdFilePath)
			if hashErr == nil {
				sentMap[mdFilePath] = fileHash
			}

			// Only delay if email was actually sent (and not last file)
			if emailSent && i < len(mdFiles)-1 && *delaySeconds > 0 {
				fmt.Printf("Waiting %d seconds before processing next file...\n", *delaySeconds)
				time.Sleep(time.Duration(*delaySeconds) * time.Second)
			}
		}
		fmt.Println()
	}

	fmt.Printf("Processing complete: %d succeeded, %d failed\n", successCount, errorCount)

	if errorCount > 0 {
		os.Exit(1)
	}
}

// renderMarkdownToHTML converts markdown to HTML with syntax highlighting
func renderMarkdownToHTML(markdown string) (string, error) {
	// Configure goldmark with GFM extensions
	md := goldmark.New(
		goldmark.WithExtensions(
			extension.GFM,
			extension.Typographer,
		),
		goldmark.WithParserOptions(
			parser.WithAutoHeadingID(),
		),
		goldmark.WithRendererOptions(
			renderer.WithNodeRenderers(),
		),
	)

	// Convert markdown to HTML
	var buf bytes.Buffer
	if err := md.Convert([]byte(markdown), &buf); err != nil {
		return "", fmt.Errorf("failed to convert markdown: %w", err)
	}

	html := buf.String()

	// Apply syntax highlighting to code blocks
	html, err := highlightCodeBlocks(html)
	if err != nil {
		return "", fmt.Errorf("failed to highlight code: %w", err)
	}

	// Wrap in markdown-here-wrapper div
	html = `<div class="markdown-here-wrapper">` + html + `</div>`

	// Wrap in proper HTML document structure
	html = `<!DOCTYPE html>
<html>
<head>
	<meta charset="UTF-8">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>
<body>
` + html + `
</body>
</html>`

	return html, nil
}

// highlightCodeBlocks applies syntax highlighting to code blocks in HTML
func highlightCodeBlocks(htmlStr string) (string, error) {
	doc, err := goquery.NewDocumentFromReader(strings.NewReader(htmlStr))
	if err != nil {
		return htmlStr, fmt.Errorf("failed to parse HTML: %w", err)
	}

	// Find all code blocks (pre > code)
	doc.Find("pre code").Each(func(i int, s *goquery.Selection) {
		codeText := s.Text()
		if codeText == "" {
			return
		}

		// Get language from class attribute (e.g., class="language-go")
		lang := ""
		class, exists := s.Attr("class")
		if exists {
			// Extract language from class like "language-go" or "hljs language-go"
			parts := strings.Fields(class)
			for _, part := range parts {
				if strings.HasPrefix(part, "language-") {
					lang = strings.TrimPrefix(part, "language-")
					break
				}
			}
		}
		// Also check parent pre element for language class
		if lang == "" {
			pre := s.Parent()
			if pre.Is("pre") {
				preClass, exists := pre.Attr("class")
				if exists {
					parts := strings.Fields(preClass)
					for _, part := range parts {
						if strings.HasPrefix(part, "language-") {
							lang = strings.TrimPrefix(part, "language-")
							break
						}
					}
				}
			}
		}

		// Determine lexer
		var lexer chroma.Lexer
		if lang != "" {
			lexer = lexers.Get(lang)
		}
		if lexer == nil {
			// Try to auto-detect
			lexer = lexers.Analyse(codeText)
		}
		if lexer == nil {
			lexer = lexers.Fallback
		}

		// Tokenize
		iterator, err := lexer.Tokenise(nil, codeText)
		if err != nil {
			return
		}

		// Format with HTML
		formatter := chromahtml.New(
			chromahtml.WithClasses(true),
			chromahtml.ClassPrefix("hljs-"),
		)

		var buf bytes.Buffer
		err = formatter.Format(&buf, styles.GitHub, iterator)
		if err != nil {
			return
		}

		// Replace the code content with highlighted version
		highlightedHTML := buf.String()
		// Extract just the code content (chromahtml wraps it in <pre><code>)
		// We need to extract the inner content
		highlightedDoc, err := goquery.NewDocumentFromReader(strings.NewReader(highlightedHTML))
		if err == nil {
			highlightedCode := highlightedDoc.Find("code").First()
			if highlightedCode.Length() > 0 {
				innerHTML, _ := highlightedCode.Html()
				s.SetHtml(innerHTML)
				// Add hljs class to code element
				s.AddClass("hljs")
			}
		}
	})

	// Get the modified HTML
	result, err := doc.Html()
	if err != nil {
		return htmlStr, fmt.Errorf("failed to get HTML: %w", err)
	}

	// Remove the outer html/body tags that goquery adds
	result = strings.TrimPrefix(result, "<html><head></head><body>")
	result = strings.TrimSuffix(result, "</body></html>")

	return result, nil
}

// inlineCSS inlines CSS styles into HTML elements for email compatibility
func inlineCSS(html string) (string, error) {
	// Combine CSS
	css := defaultCSS + "\n" + githubCSS

	// Embed CSS in a style tag within the HTML
	htmlWithCSS := fmt.Sprintf(`<style type="text/css">%s</style>%s`, css, html)

	// Use premailer to inline CSS
	options := premailer.NewOptions()
	options.RemoveClasses = false
	options.CssToAttributes = true

	premailerInstance, err := premailer.NewPremailerFromString(htmlWithCSS, options)
	if err != nil {
		return "", fmt.Errorf("failed to create premailer: %w", err)
	}

	// Inline styles
	htmlInlined, err := premailerInstance.Transform()
	if err != nil {
		return "", fmt.Errorf("failed to inline CSS: %w", err)
	}

	return htmlInlined, nil
}

// composeEmail creates a properly formatted email message with multipart/alternative structure
func composeEmail(from string, to []string, subject, body string, useMarkdown bool) string {
	var message strings.Builder

	// Add email headers
	replyTo := from // Default reply-to to sender
	message.WriteString(addEmailHeaders(from, to, subject, replyTo))

	if useMarkdown {
		// Convert markdown to HTML
		html, err := renderMarkdownToHTML(body)
		if err != nil {
			fmt.Printf("Warning: Failed to render markdown, sending as plain text: %v\n", err)
			// Fallback to plain text only
			message.WriteString("Content-Type: text/plain; charset=UTF-8\r\n")
			message.WriteString("Content-Transfer-Encoding: quoted-printable\r\n")
			message.WriteString("\r\n")
			plainTextEncoded, _ := encodeQuotedPrintable(body)
			message.WriteString(plainTextEncoded)
			return message.String()
		}

		// Inline CSS for email compatibility
		html, err = inlineCSS(html)
		if err != nil {
			fmt.Printf("Warning: Failed to inline CSS: %v\n", err)
			// Continue with HTML anyway
		}

		// Create plain text version from HTML
		plainText := htmlToPlainText(html)
		if plainText == "" {
			// Fallback to original body if HTML parsing fails
			plainText = body
		}

		// Create multipart/alternative email
		multipartBody, boundary, err := createMultipartEmail(plainText, html)
		if err != nil {
			fmt.Printf("Warning: Failed to create multipart email, sending HTML only: %v\n", err)
			// Fallback to HTML only
			message.WriteString("Content-Type: text/html; charset=UTF-8\r\n")
			message.WriteString("Content-Transfer-Encoding: quoted-printable\r\n")
			message.WriteString("\r\n")
			htmlEncoded, _ := encodeQuotedPrintable(html)
			message.WriteString(htmlEncoded)
			return message.String()
		}

		// Set multipart content type with the boundary used
		message.WriteString(fmt.Sprintf("Content-Type: multipart/alternative; boundary=\"%s\"\r\n", boundary))
		message.WriteString("\r\n")
		message.WriteString(multipartBody)
	} else {
		// Plain text mode only
		message.WriteString("Content-Type: text/plain; charset=UTF-8\r\n")
		message.WriteString("Content-Transfer-Encoding: quoted-printable\r\n")
		message.WriteString("\r\n")
		plainTextEncoded, _ := encodeQuotedPrintable(body)
		message.WriteString(plainTextEncoded)
	}

	return message.String()
}

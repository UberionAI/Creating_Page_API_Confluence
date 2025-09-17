package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"text/template"
	"time"

	"github.com/joho/godotenv"
	"golang.org/x/crypto/ssh"
)

// --------------------------------------------------
// Simple refactor: connect to single VM (from .env) via SSH,
// run a long single-line command under sudo, collect output,
// transform it into Confluence "storage" HTML and create/update a page.
// --------------------------------------------------

// Config holds runtime configuration loaded from .env
type Config struct {
	SSHUsername     string
	SSHPassword     string
	SSHSudoPassword string
	SSHHostname     string

	ConfluenceHost  string // host[:port] or full URL
	ConfluenceUser  string
	ConfluencePass  string
	ConfluenceSpace string
}

// Confluence client
type ConfluenceClient struct {
	BaseURL    string
	User       string
	Password   string
	Space      string
	HTTPClient *http.Client
}

// PageData contains parsed values to inject into Confluence template
type PageData struct {
	Title            string
	Hostname         string
	OS               string
	VCPU             string
	RAM              string
	DiskTotal        string
	DiskCount        string
	IfConfig         string
	Routes           string
	Iptables         string
	Lsblk            string
	Df               string
	ServicesActive   string
	ServicesInactive string
	Users            string
	GeneratedAt      string
}

func main() {
	// Flags
	cmdFlag := flag.String("commands", "", "Semicolon-separated list of commands to run (single-line)")
	cmdFileFlag := flag.String("command-file", "", "Path to file containing commands (one per line) - will be joined with ';')")
	titleFlag := flag.String("title", "", "Optional page title (default: Паспорт VM: <hostname>)")
	envFile := flag.String("env", ".env", "Path to .env file")
	flag.Parse()

	// Load .env
	if err := godotenv.Load(*envFile); err != nil {
		log.Fatalf("failed to load %s: %v", *envFile, err)
	}

	cfg := Config{
		SSHUsername:     os.Getenv("SSH_USERNAME"),
		SSHPassword:     os.Getenv("SSH_PASSWORD"),
		SSHSudoPassword: os.Getenv("SSH_SUDO_PASSWORD"),
		SSHHostname:     os.Getenv("SSH_HOSTNAME"),

		ConfluenceHost:  os.Getenv("CONFLUENCE_IP"),
		ConfluenceUser:  os.Getenv("CONFLUENCE_USER"),
		ConfluencePass:  os.Getenv("CONFLUENCE_PASSWORD"),
		ConfluenceSpace: os.Getenv("CONFLUENCE_SPACE"),
	}

	// Basic validation
	if cfg.SSHUsername == "" || cfg.SSHPassword == "" || cfg.SSHSudoPassword == "" || cfg.SSHHostname == "" {
		// Note: user asked to provide hostname in .env and not use VM_ListSSH.txt
		log.Fatal("Missing SSH credentials or SSH_HOSTNAME in .env (SSH_USERNAME, SSH_PASSWORD, SSH_SUDO_PASSWORD, SSH_HOSTNAME required)")
	}
	if cfg.ConfluenceHost == "" || cfg.ConfluenceUser == "" || cfg.ConfluencePass == "" || cfg.ConfluenceSpace == "" {
		log.Fatal("Missing Confluence credentials in .env (CONFLUENCE_IP, CONFLUENCE_USER, CONFLUENCE_PASSWORD, CONFLUENCE_SPACE required)")
	}

	// Build commands list
	var userCommand string
	if *cmdFileFlag != "" {
		b, err := os.ReadFile(*cmdFileFlag)
		if err != nil {
			log.Fatalf("error reading command file: %v", err)
		}
		// join lines with ';' keeping them safe
		lines := []string{}
		for _, ln := range strings.Split(string(b), "\n") {
			ln = strings.TrimSpace(ln)
			if ln != "" {
				lines = append(lines, ln)
			}
		}
		userCommand = strings.Join(lines, " ; ")
	} else if *cmdFlag != "" {
		userCommand = *cmdFlag
	} else {
		// Default optimized single-line command (produces labeled sections)
		userCommand = buildDefaultOneLineCommand()
	}

	// Prepare SSH config
	sshCfg := &ssh.ClientConfig{
		User:            cfg.SSHUsername,
		Auth:            []ssh.AuthMethod{ssh.Password(cfg.SSHPassword)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         30 * time.Second,
	}

	// Execute remote command (single host only)
	stdout, stderr, err := runSSHCommand(cfg.SSHHostname, sshCfg, cfg.SSHSudoPassword, userCommand)
	if err != nil {
		log.Fatalf("ssh command failed: %v; stderr: %s", err, stderr)
	}

	// Parse output into structured fields
	sections := parseLabeledOutput(stdout)

	// Prepare page data
	page := PageData{
		Hostname:         strings.TrimSpace(sections["HOSTNAME"]),
		OS:               strings.TrimSpace(sections["OS"]),
		VCPU:             strings.TrimSpace(sections["VCPU"]),
		RAM:              strings.TrimSpace(sections["RAM"]),
		DiskTotal:        strings.TrimSpace(sections["DISK_TOTAL"]),
		DiskCount:        strings.TrimSpace(sections["DISK_COUNT"]),
		IfConfig:         strings.TrimSpace(sections["IFCONFIG"]),
		Routes:           strings.TrimSpace(sections["ROUTES"]),
		Iptables:         strings.TrimSpace(sections["IPTABLES"]),
		Lsblk:            strings.TrimSpace(sections["LSBLK"]),
		Df:               strings.TrimSpace(sections["DF"]),
		ServicesActive:   strings.TrimSpace(sections["SERVICES_ACTIVE"]),
		ServicesInactive: strings.TrimSpace(sections["SERVICES_INACTIVE"]),
		Users:            strings.TrimSpace(sections["USERS"]),
		GeneratedAt:      strings.TrimSpace(sections["DATE"]),
	}

	if *titleFlag != "" {
		page.Title = *titleFlag
	} else if page.Hostname != "" {
		page.Title = fmt.Sprintf("Паспорт VM: %s", page.Hostname)
	} else {
		page.Title = fmt.Sprintf("Паспорт VM: %s", cfg.SSHHostname)
	}

	// Build Confluence client
	baseURL := normalizeConfluenceURL(cfg.ConfluenceHost)
	client := ConfluenceClient{
		BaseURL:    baseURL,
		User:       cfg.ConfluenceUser,
		Password:   cfg.ConfluencePass,
		Space:      cfg.ConfluenceSpace,
		HTTPClient: &http.Client{Timeout: 30 * time.Second},
	}

	// Render body
	bodyHTML, err := renderConfluenceTemplate(page)
	if err != nil {
		log.Fatalf("template render error: %v", err)
	}

	// Create or update page
	resURL, err := client.CreateOrUpdatePage(page.Title, bodyHTML)
	if err != nil {
		log.Fatalf("confluence error: %v", err)
	}

	fmt.Printf("Confluence page created/updated: %s\n", resURL)
}

// --------------------------------------------------
// Helper functions
// --------------------------------------------------

func buildDefaultOneLineCommand() string {
	parts := []string{
		"echo '###HOSTNAME' ; hostname",
		`echo '###OS' ; cat /etc/os-release | grep PRETTY_NAME | cut -d= -f2 | tr -d '"' || true`,
		"echo '###VCPU' ; nproc || true",
		`echo '###RAM' ; free -h | awk '/Mem:/{print $2}' || true`,
		`echo '###DISK_TOTAL' ; lsblk -b -d -o SIZE -n | awk '{s+=$1} END{printf "%.0fG\n", s/1024/1024/1024}' || true`,
		`echo '###DISK_COUNT' ; lsblk | grep -c ' disk' || true`,
		`echo '###IFCONFIG' ; grep -E '^\s*iface\s+\S+' /etc/network/interfaces | awk '{print $2}' | while read i; do ip -o -4 addr show $i | awk '{print $2, $4}'; done || true`,
		`echo '###ROUTES' ; ip route show || true`,
		`echo '###IPTABLES' ; ( \
			echo "# === filter ===" ; iptables -t filter -L -n -v --line-numbers ; \
			echo "# === nat ===" ; iptables -t nat -L -n -v --line-numbers ; \
			echo "# === mangle ===" ; iptables -t mangle -L -n -v --line-numbers ; \
			echo "# === raw ===" ; iptables -t raw -L -n -v --line-numbers ; \
			echo "# === security ===" ; iptables -t security -L -n -v --line-numbers \
		) || true`,
		`echo '###LSBLK' ; lsblk -o NAME,SIZE,FSTYPE,MOUNTPOINT || true`,
		`echo '###DF' ; df -h || true`,
		`echo '###SERVICES_ACTIVE' ; systemctl list-units --type=service --state=running --no-pager --no-legend | head -15 || true`,
		`echo '###SERVICES_INACTIVE' ; systemctl list-units --type=service --state=inactive --no-pager --no-legend | head -10 || true`,
		`echo '###USERS' ; getent passwd | grep -v '/nologin\|/false' | cut -d: -f1 | head -5 | while read u; do echo "$u: $(id -nG $u)"; done || true`,
		`echo '###DATE' ; date '+%F %T %z'`,
	}
	return strings.Join(parts, " ; ")
}

// runSSHCommand connects to host:22 and runs the supplied `command` under sudo
func runSSHCommand(host string, sshCfg *ssh.ClientConfig, sudoPassword, command string) (string, string, error) {
	addr := host
	if !strings.Contains(addr, ":") {
		addr = addr + ":22"
	}
	client, err := ssh.Dial("tcp", addr, sshCfg)
	if err != nil {
		return "", "", fmt.Errorf("ssh dial: %w", err)
	}
	defer client.Close()

	sess, err := client.NewSession()
	if err != nil {
		return "", "", fmt.Errorf("new session: %w", err)
	}
	defer sess.Close()

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	sess.Stdout = &stdout
	sess.Stderr = &stderr

	// Escape single quotes in both password and command so we can safely embed them in single-quoted bash -lc
	escPass := escapeSingleQuote(sudoPassword)
	escCmd := escapeSingleQuote(command)
	full := fmt.Sprintf("echo '%s' | sudo -S -p '' bash -lc '%s'", escPass, escCmd)

	// Run
	if err := sess.Run(full); err != nil {
		// return stdout and stderr too
		return stdout.String(), stderr.String(), fmt.Errorf("session run: %w", err)
	}
	return stdout.String(), stderr.String(), nil
}

// escapeSingleQuote replaces ' with '\"'"' pattern so it can be safely included inside a single-quoted shell string
func escapeSingleQuote(s string) string {
	// In shell single-quoted string, to embed a single quote you close, add "'" and reopen. The pattern is: 'abc'"'"'def'
	return strings.ReplaceAll(s, "'", "'\"'\"'")
}

// parseLabeledOutput reads sections that start with lines like ###NAME
func parseLabeledOutput(out string) map[string]string {
	lines := strings.Split(out, "\n")
	sections := map[string][]string{}
	current := ""
	for _, ln := range lines {
		if strings.HasPrefix(ln, "###") {
			current = strings.TrimSpace(strings.TrimPrefix(ln, "###"))
			sections[current] = []string{}
			continue
		}
		if current != "" {
			sections[current] = append(sections[current], ln)
		}
	}
	outMap := map[string]string{}
	for k, v := range sections {
		outMap[k] = strings.TrimSpace(strings.Join(v, "\n"))
	}
	return outMap
}

// normalizeConfluenceURL ensures scheme present
func normalizeConfluenceURL(raw string) string {
	if strings.HasPrefix(raw, "http://") || strings.HasPrefix(raw, "https://") {
		return strings.TrimRight(raw, "/")
	}
	// default to http if scheme not provided
	return "http://" + strings.TrimRight(raw, "/")
}

// Render Confluence storage format template using PageData
func renderConfluenceTemplate(p PageData) (string, error) {
	const tpl = `
<table class="wrapped">
  <colgroup>
    <col />
    <col />
  </colgroup>
  <tbody>
    <tr>
      <th colspan="2">Основная информация</th>
    </tr>
    <tr>
      <td><strong>Hostname</strong></td>
      <td>{{.Hostname}}</td>
    </tr>
    <tr>
      <td><strong>Дистрибутив</strong></td>
      <td>{{.OS}}</td>
    </tr>
    <tr>
      <td><strong>IP ВМ</strong></td>
      <td>{{.IfConfig}}</td>
    </tr>
  </tbody>
</table>

<h2>Аппаратные характеристики</h2>
<table class="wrapped">
  <colgroup>
    <col />
    <col />
  </colgroup>
  <tbody>
    <tr>
      <td><strong>vCPU</strong></td>
      <td>{{.VCPU}}</td>
    </tr>
    <tr>
      <td><strong>RAM</strong></td>
      <td>{{.RAM}}</td>
    </tr>
    <tr>
      <td><strong>Общий объём HDD</strong></td>
      <td>{{.DiskTotal}}</td>
    </tr>
    <tr>
      <td><strong>Количество дисков</strong></td>
      <td>{{.DiskCount}}</td>
    </tr>
  </tbody>
</table>

<h2>Сетевые интерфейсы</h2>
<ac:structured-macro ac:name="code" ac:schema-version="1">
  <ac:parameter ac:name="language">bash</ac:parameter>
  <ac:plain-text-body><![CDATA[{{.IfConfig}}]]></ac:plain-text-body>
</ac:structured-macro>

<h2>Маршрутизация</h2>
<ac:structured-macro ac:name="code" ac:schema-version="1">
  <ac:parameter ac:name="language">bash</ac:parameter>
  <ac:plain-text-body><![CDATA[{{.Routes}}]]></ac:plain-text-body>
</ac:structured-macro>

<h2>iptables</h2>
<ac:structured-macro ac:name="code" ac:schema-version="1">
  <ac:parameter ac:name="language">bash</ac:parameter>
  <ac:plain-text-body><![CDATA[{{.Iptables}}]]></ac:plain-text-body>
</ac:structured-macro>

<h2>lsblk</h2>
<ac:structured-macro ac:name="code" ac:schema-version="1">
  <ac:parameter ac:name="language">bash</ac:parameter>
  <ac:plain-text-body><![CDATA[{{.Lsblk}}]]></ac:plain-text-body>
</ac:structured-macro>

<h2>df -h</h2>
<ac:structured-macro ac:name="code" ac:schema-version="1">
  <ac:parameter ac:name="language">bash</ac:parameter>
  <ac:plain-text-body><![CDATA[{{.Df}}]]></ac:plain-text-body>
</ac:structured-macro>

<h2>Активные сервисы</h2>
<ac:structured-macro ac:name="code" ac:schema-version="1">
  <ac:parameter ac:name="language">bash</ac:parameter>
  <ac:plain-text-body><![CDATA[{{.ServicesActive}}]]></ac:plain-text-body>
</ac:structured-macro>

<h2>Неактивные сервисы</h2>
<ac:structured-macro ac:name="code" ac:schema-version="1">
  <ac:parameter ac:name="language">bash</ac:parameter>
  <ac:plain-text-body><![CDATA[{{.ServicesInactive}}]]></ac:plain-text-body>
</ac:structured-macro>

<h2>Пользователи системы</h2>
<ac:structured-macro ac:name="code" ac:schema-version="1">
  <ac:parameter ac:name="language">bash</ac:parameter>
  <ac:plain-text-body><![CDATA[{{.Users}}]]></ac:plain-text-body>
</ac:structured-macro>

<h2>Дата отчёта</h2>
<p>{{.GeneratedAt}}</p>
`
	t := template.Must(template.New("cf").Parse(tpl))
	var buf bytes.Buffer
	if err := t.Execute(&buf, p); err != nil {
		return "", err
	}
	return buf.String(), nil
}

// CreateOrUpdatePage creates a page (or updates if title exists)
func (c *ConfluenceClient) CreateOrUpdatePage(title, bodyStorage string) (string, error) {
	// 1) lookup existing page
	foundID, version, found, err := c.findPageByTitle(title)
	if err != nil {
		return "", fmt.Errorf("find page: %w", err)
	}

	basic := "Basic " + base64.StdEncoding.EncodeToString([]byte(c.User+":"+c.Password))

	if found {
		// Update
		url := fmt.Sprintf("%s/rest/api/content/%s", c.BaseURL, foundID)
		payload := map[string]interface{}{
			"id":      foundID,
			"type":    "page",
			"title":   title,
			"space":   map[string]string{"key": c.Space},
			"body":    map[string]map[string]string{"storage": {"value": bodyStorage, "representation": "storage"}},
			"version": map[string]interface{}{"number": version + 1},
		}
		b, _ := json.Marshal(payload)
		req, _ := http.NewRequest("PUT", url, bytes.NewReader(b))
		req.Header.Set("Authorization", basic)
		req.Header.Set("Content-Type", "application/json")
		resp, err := c.HTTPClient.Do(req)
		if err != nil {
			return "", fmt.Errorf("confluence put: %w", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			body, _ := io.ReadAll(resp.Body)
			return "", fmt.Errorf("confluence update failed: %s - %s", resp.Status, string(body))
		}
		// return link
		return fmt.Sprintf("%s/pages/viewpage.action?pageId=%s", c.BaseURL, foundID), nil
	}

	// Create new
	url := fmt.Sprintf("%s/rest/api/content", c.BaseURL)
	payload := map[string]interface{}{
		"type":  "page",
		"title": title,
		"space": map[string]string{"key": c.Space},
		"body":  map[string]map[string]string{"storage": {"value": bodyStorage, "representation": "storage"}},
	}
	b, _ := json.Marshal(payload)
	req, _ := http.NewRequest("POST", url, bytes.NewReader(b))
	req.Header.Set("Authorization", basic)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("confluence post: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("confluence create failed: %s - %s", resp.Status, string(body))
	}
	// parse returned JSON to get id
	var res map[string]interface{}
	_ = json.NewDecoder(resp.Body).Decode(&res)
	if id, ok := res["id"].(string); ok {
		return fmt.Sprintf("%s/pages/viewpage.action?pageId=%s", c.BaseURL, id), nil
	}
	return "", nil
}

// findPageByTitle returns id and version if exists
func (c *ConfluenceClient) findPageByTitle(title string) (string, int, bool, error) {
	q := fmt.Sprintf("%s/rest/api/content?spaceKey=%s&title=%s&expand=version", c.BaseURL, url.QueryEscape(c.Space), url.QueryEscape(title))
	basic := "Basic " + base64.StdEncoding.EncodeToString([]byte(c.User+":"+c.Password))
	req, _ := http.NewRequest("GET", q, nil)
	req.Header.Set("Authorization", basic)
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return "", 0, false, fmt.Errorf("confluence GET: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return "", 0, false, fmt.Errorf("confluence search failed: %s - %s", resp.Status, string(body))
	}
	var result struct {
		Results []struct {
			Id      string `json:"id"`
			Version struct {
				Number int `json:"number"`
			} `json:"version"`
		} `json:"results"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", 0, false, fmt.Errorf("decode response: %w", err)
	}
	if len(result.Results) > 0 {
		return result.Results[0].Id, result.Results[0].Version.Number, true, nil
	}
	return "", 0, false, nil
}

package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/json"
	"fmt"
	"html"
	"image/color"
	"io"
	"math"
	"math/big"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"

	"github-scanner/internal/collector"
)

type Repo struct {
	Name     string `json:"name"`
	CloneURL string `json:"clone_url"`
	Private  bool   `json:"private"`
	// Size — размер репозитория в КБ (так GitHub отдаёт поле size).
	Size int64 `json:"size"`
}

// Лимиты одного репозитория: без них гигантские репо (крон на 460 МБ)
// подвешивали скан — git clone и git log -p по всей истории gitleaks
// гонял минутами без всякого прогресса.
const (
	maxRepoSizeKB = 300 * 1024       // 300 МБ — дальше не клонируем
	cloneTimeout  = 5 * time.Minute  // лимит на git clone
	gitleaksTout  = 10 * time.Minute // лимит на gitleaks по одному репо
)

type Scanner struct {
	mu      sync.Mutex
	cancel  context.CancelFunc
	running bool
}

func (s *Scanner) stop() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cancel != nil {
		s.cancel()
	}
}

// githubAPI: отдельный клиент с таймаутом. У http.DefaultClient таймаута нет,
// зависшее соединение держало бы скан вечно (спасал только ctx).
var githubAPI = &http.Client{Timeout: 60 * time.Second}

// githubRepos: репозитории пользователя постранично, с разбором rate limit
// (403/429 + X-RateLimit-Reset) — ровно как в collector.search. Раньше
// 403 от GitHub Core API превращался в [ERROR] и обрывал весь аккаунт,
// хотя лимит 5000/ч упирается на длинных списках обязательно.
func githubRepos(ctx context.Context, token, user string) ([]Repo, error) {
	var all []Repo
	const maxAttempts = 5
	for page := 1; ; page++ {
		url := "https://api.github.com/users/" + user +
			"/repos?per_page=100&page=" + strconv.Itoa(page)

		var body []byte
		var status int
		for attempt := 1; ; attempt++ {
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
			if err != nil {
				return nil, err
			}
			req.Header.Set("Accept", "application/vnd.github+json")
			req.Header.Set("Authorization", "Bearer "+token)
			req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

			resp, err := githubAPI.Do(req)
			if err != nil {
				return nil, err
			}
			b, rerr := io.ReadAll(resp.Body)
			resp.Body.Close()
			if rerr != nil {
				return nil, rerr
			}
			status, body = resp.StatusCode, b

			if status != http.StatusForbidden && status != http.StatusTooManyRequests {
				break
			}
			if attempt >= maxAttempts {
				return nil, fmt.Errorf("GitHub API: HTTP %d после %d попыток: %s",
					status, attempt, strings.TrimSpace(string(body)))
			}
			wait := time.Duration(attempt*15) * time.Second
			if reset := resp.Header.Get("X-RateLimit-Reset"); reset != "" {
				if ts, perr := strconv.ParseInt(reset, 10, 64); perr == nil {
					if d := time.Until(time.Unix(ts, 0)); d > wait && d < time.Hour {
						wait = d + time.Second
					}
				}
			}
			// Ожидание прерывается по ctx: STOP срабатывает сразу.
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(wait):
			}
		}

		if status != http.StatusOK {
			return nil, fmt.Errorf("GitHub API: HTTP %d: %s",
				status, strings.TrimSpace(string(body)))
		}
		var repos []Repo
		if err := json.Unmarshal(body, &repos); err != nil {
			return nil, err
		}
		if len(repos) == 0 {
			break
		}
		all = append(all, repos...)
		if len(repos) < 100 {
			break
		}
	}
	return all, nil
}

// findTool: PATH + стандартные места установки Go-инструментов.
func findTool(name string) (string, error) {
	path, err := exec.LookPath(name)
	if err == nil {
		return path, nil
	}
	candidates := []string{
		filepath.Join(os.Getenv("HOME"), "go", "bin", name),
		filepath.Join("/usr", "local", "bin", name),
		filepath.Join("/usr", "bin", name),
	}
	for _, c := range candidates {
		if st, statErr := os.Stat(c); statErr == nil && !st.IsDir() && st.Mode()&0o111 != 0 {
			return c, nil
		}
	}
	return "", err
}

// keepAwake: systemd-inhibit держит inhibit-lock из рабочей горутины.
func keepAwake(reason string) (done func()) {
	cmd := exec.Command("systemd-inhibit",
		"--who=github-scanner",
		"--what=sleep:idle",
		"--why="+reason,
		"sleep", "infinity",
	)
	if err := cmd.Start(); err != nil {
		return func() {}
	}
	return func() {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		_ = cmd.Wait()
	}
}

// procPulse: раз в интервал пишет в лог CPU/RAM/размер каталога процесса.
func procPulse(stop <-chan struct{}, done <-chan struct{}, pid int, workDir string, log *logView, interval time.Duration) {
	var lastCPU float64
	tick := time.NewTicker(interval)
	defer tick.Stop()
	start := time.Now()

	readCPU := func(pid int) float64 {
		data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
		if err != nil {
			return -1
		}
		fields := strings.Fields(string(data))
		if len(fields) < 15 {
			return -1
		}
		utime, _ := strconv.ParseFloat(fields[13], 64)
		stime, _ := strconv.ParseFloat(fields[14], 64)
		return (utime + stime) / 100.0
	}

	readRSS := func(pid int) int {
		data, err := os.ReadFile(fmt.Sprintf("/proc/%d/statm", pid))
		if err != nil {
			return 0
		}
		fields := strings.Fields(string(data))
		if len(fields) < 2 {
			return 0
		}
		rss, _ := strconv.Atoi(fields[1])
		return rss * 4096 / 1024 / 1024
	}

	dirSize := func(path string) int {
		var total int64
		_ = filepath.Walk(path, func(_ string, info os.FileInfo, err error) error {
			if err == nil && !info.IsDir() {
				total += info.Size()
			}
			return nil
		})
		return int(total / 1024 / 1024)
	}

	for {
		select {
		case <-stop:
			return
		case <-done:
			return
		case <-tick.C:
			cpu := readCPU(pid)
			if cpu < 0 {
				return
			}
			dCPU := cpu - lastCPU
			lastCPU = cpu
			rss := readRSS(pid)
			size := dirSize(workDir)
			state := "РАБОТАЕТ"
			if lastCPU > 0 && dCPU < 0.05 {
				state = "БЕЗ ПРОГРЕССА?"
			}
			log.append("    [пульс] %s | прошло %s | CPU %0.0fс (+%0.0fс) | RAM %dМБ | репо %dМБ",
				state, time.Since(start).Round(time.Second), cpu, dCPU, rss, size)
		}
	}
}

//go:embed gitleaks.toml
var gitleaksConfigTOML string

// gitleaksConfigPath раскладывает встроенный конфиг (дефолтные правила
// gitleaks + крипто-правила BIP39/WIF/xprv, которых в стандартном ruleset
// нет) во временный файл — gitleaks читает конфиг только из файла или env.
// Пустая строка — файл создать не удалось, вызов идёт без --config.
var gitleaksConfigPath = sync.OnceValue(func() string {
	f, err := os.CreateTemp("", "github-scanner-gitleaks-*.toml")
	if err != nil {
		return ""
	}
	_, _ = f.WriteString(gitleaksConfigTOML)
	_ = f.Close()
	return f.Name()
})

// gitleaksConfigArgs — флаги --config со встроенным конфигом или nil,
// если файл создать не удалось (gitleaks возьмёт дефолтный ruleset).
func gitleaksConfigArgs() []string {
	if p := gitleaksConfigPath(); p != "" {
		return []string{"--config", p}
	}
	return nil
}

func runCommandStream(ctx context.Context, dir string, onLine func(line string), onPID func(int), name string, args ...string) (string, int, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = dir

	var out bytes.Buffer
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return "", -1, err
	}
	cmd.Stderr = cmd.Stdout

	if err := cmd.Start(); err != nil {
		return "", -1, err
	}
	if onPID != nil && cmd.Process != nil {
		onPID(cmd.Process.Pid)
	}

	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		out.WriteString(line)
		out.WriteByte('\n')
		if onLine != nil {
			onLine(line)
		}
	}

	scanErr := scanner.Err()
	waitErr := cmd.Wait()

	exitCode := 0
	if waitErr != nil {
		if ctx.Err() != nil {
			return out.String(), -1, ctx.Err()
		}
		if ee, ok := waitErr.(*exec.ExitError); ok {
			exitCode = ee.ExitCode()
		} else {
			return out.String(), -1, waitErr
		}
	}
	// scanner.Err() раньше игнорировался: строка длиннее лимита буфера молча
	// обрезала остаток вывода. Ошибку возвращаем вместе с кодом выхода —
	// вызывающий логирует её, но прогон по-прежнему оценивается по code.
	if scanErr != nil && ctx.Err() == nil {
		return out.String(), exitCode, fmt.Errorf("чтение вывода команды: %w", scanErr)
	}
	return out.String(), exitCode, nil
}

// logView — «терминал»: зелёный моноширинный текст на тёмном фоне.
//
// ВАЖНО: строки копятся в lines синхронно (их читает SAVE LOG), а сам
// widget.TextGrid меняется ТОЛЬКО внутри fyne.Do. Мутация виджета из фоновой
// горутины минуя главный поток Fyne — гонка с рендером (прежний код ровно
// это и делал: Append/SetRowStyle шли напрямую, а fyne.Do оборачивал лишь
// Refresh). lines[i] хранится так же, как строки сетки: поэлементно на «\n».
type logView struct {
	grid   *widget.TextGrid
	styled int
	lines  []string
	mu     sync.Mutex
}

var (
	terminalStyle = &widget.CustomTextGridStyle{
		FGColor: color.NRGBA{R: 0x2e, G: 0xe0, B: 0x5a, A: 0xff},
		BGColor: color.NRGBA{R: 0x11, G: 0x14, B: 0x18, A: 0xff},
	}
	findingsStyle = &widget.CustomTextGridStyle{
		FGColor: color.NRGBA{R: 0xff, G: 0xa5, B: 0x1a, A: 0xff},
		BGColor: color.NRGBA{R: 0x1f, G: 0x16, B: 0x08, A: 0xff},
	}
	errorStyle = &widget.CustomTextGridStyle{
		FGColor: color.NRGBA{R: 0xff, G: 0x55, B: 0x55, A: 0xff},
		BGColor: color.NRGBA{R: 0x20, G: 0x10, B: 0x10, A: 0xff},
	}
	dimStyle = &widget.CustomTextGridStyle{
		FGColor: color.NRGBA{R: 0x7f, G: 0xb8, B: 0x7f, A: 0xff},
		BGColor: color.NRGBA{R: 0x11, G: 0x14, B: 0x18, A: 0xff},
	}
)

func stripANSI(s string) string {
	var b strings.Builder
	inEsc := false
	for _, r := range s {
		switch {
		case r == '\x1b':
			inEsc = true
		case inEsc:
			if r == 'm' || r == 'K' {
				inEsc = false
			}
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

func styleFor(line string) widget.TextGridStyle {
	switch {
	case strings.Contains(line, "[FINDINGS]"):
		return findingsStyle
	case strings.Contains(line, "ERROR") || strings.Contains(line, "[WARN]"):
		return errorStyle
	case strings.HasPrefix(line, "    "):
		return dimStyle
	default:
		return terminalStyle
	}
}

func newLogView() *logView {
	grid := widget.NewTextGrid()
	grid.Scroll = fyne.ScrollBoth
	return &logView{grid: grid}
}

func (l *logView) append(format string, args ...interface{}) {
	text := fmt.Sprintf(format, args...)

	l.mu.Lock()
	l.lines = append(l.lines, strings.Split(text, "\n")...)
	l.mu.Unlock()

	// Вся мутация сетки — в главном потоке Fyne. fyne.Do не блокируется
	// при вызове из обработчика кнопки (очередь unbounded), поэтому из
	// main-горутины тоже безопасно.
	fyne.Do(func() {
		l.grid.Append(text)
		for r := l.styled; r < len(l.grid.Rows); r++ {
			l.grid.SetRowStyle(r, styleFor(l.grid.RowText(r)))
		}
		l.styled = len(l.grid.Rows)
	})
}

func (l *logView) clear() {
	l.mu.Lock()
	l.lines = nil
	l.mu.Unlock()
	fyne.Do(func() {
		l.grid.SetText("")
		l.styled = 0
	})
}

// text возвращает ВСЕ строки, включая ещё не отрисованные — иначе SAVE LOG
// мог бы не дождаться записей из фоновой горутины.
func (l *logView) text() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return strings.Join(l.lines, "\n")
}

func (l *logView) widget() fyne.CanvasObject {
	return l.grid
}

// openBrowser открывает файл/URL в браузере по умолчанию.
func openBrowser(url string) {
	cmds := [][]string{
		{"xdg-open", url},
		{"gio", "open", url},
	}
	for _, c := range cmds {
		if _, err := exec.LookPath(c[0]); err == nil {
			if err := exec.Command(c[0], c[1:]...).Start(); err == nil {
				return
			}
		}
	}
}

// openFolder открывает каталог в файловом менеджере.
func openFolder(path string) error {
	cmds := [][]string{
		{"xdg-open", path},
		{"nautilus", path},
		{"dolphin", path},
		{"thunar", path},
		{"nemo", path},
	}
	var lastErr error
	for _, c := range cmds {
		if _, err := exec.LookPath(c[0]); err != nil {
			continue
		}
		if err := exec.Command(c[0], c[1:]...).Start(); err == nil {
			return nil
		} else {
			lastErr = err
		}
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("не найден файловый менеджер (xdg-open и др.)")
	}
	return lastErr
}

// reportsDir: каталог отчётов рядом с исполняемым файлом.
func reportsDir() string {
	exe, err := os.Executable()
	if err == nil {
		return filepath.Join(filepath.Dir(exe), "reports")
	}
	return "reports"
}

// activeScans — сколько сканирований идёт прямо сейчас (обе вкладки).
var activeScans atomic.Int32

// exeDir — каталог самого исполняемого файла: рядом с ним лежат
// ai_verdict.py и другие ресурсы, даже если рабочая папка другая.
func exeDir() string {
	if exe, err := os.Executable(); err == nil {
		if resolved, rerr := filepath.EvalSymlinks(exe); rerr == nil {
			return filepath.Dir(resolved)
		}
		return filepath.Dir(exe)
	}
	return "."
}

// newScanDir создаёт папку ТОЛЬКО для текущего запуска:
// reports/scan_ГГГГММДД_ЧЧММСС. Результаты разных сканов не смешиваются.
func newScanDir() string {
	dir := filepath.Join(reportsDir(), "scan_"+time.Now().Format("20060102_150405"))
	_ = os.MkdirAll(dir, 0o755)
	return dir
}

// pickScanDir — самая свежая папка scan_*; если их нет — сам reports
// (совместимость со старыми плоскими отчётами).
func pickScanDir() string {
	entries, err := os.ReadDir(reportsDir())
	if err != nil {
		return reportsDir()
	}
	best := ""
	for _, e := range entries {
		if !e.IsDir() || !strings.HasPrefix(e.Name(), "scan_") {
			continue
		}
		if e.Name() > best { // формат имени сортируется как дата
			best = e.Name()
		}
	}
	if best == "" {
		return reportsDir()
	}
	return filepath.Join(reportsDir(), best)
}

// clearReports удаляет содержимое папки результатов (саму папку оставляет).
// Дополнительно предлагает удалить старый accounts.txt — иначе новый поиск
// снова сканирует старый список (1500 аккаунтов) и «находки» из прошлого.
// Во время сканирования очистка запрещена.
func clearReports(w fyne.Window, log *logView, fileEntry *widget.Entry) {
	if activeScans.Load() > 0 {
		dialog.ShowInformation("Идёт сканирование",
			"Сначала нажми STOP — потом очистка.", w)
		return
	}
	dialog.NewConfirm("Очистить результаты?",
		"Удалить ВСЕ отчёты и папки сканов?\n"+reportsDir(),
		func(ok bool) {
			if !ok {
				return
			}
			if activeScans.Load() > 0 {
				log.append("[ERROR] скан уже запущен — очистка отменена")
				return
			}
			entries, err := os.ReadDir(reportsDir())
			if err != nil {
				log.append("[ERROR] %v", err)
				return
			}
			n := 0
			for _, e := range entries {
				if os.RemoveAll(filepath.Join(reportsDir(), e.Name())) == nil {
					n++
				}
			}
			log.append("Очищено: %d элементов в %s", n, reportsDir())

			// Часть 2: старый список аккаунтов.
			if fileEntry != nil {
				f := strings.TrimSpace(fileEntry.Text)
				if f == "" {
					f = "accounts.txt"
				}
				if st, err := os.Stat(f); err == nil && !st.IsDir() {
					dialog.NewConfirm("Удалить и старые аккаунты?",
						"Удалить файл со старым списком аккаунтов?\n"+f+
							"\n\nБез этого новый поиск дополнит его, а скан пойдёт по старым репо.",
						func(ok2 bool) {
							if !ok2 {
								return
							}
							if err := os.Remove(f); err != nil {
								log.append("[ERROR] %v", err)
								return
							}
							fileEntry.SetText("")
							log.append("Удалён старый список: %s", f)
						}, w).Show()
				}
			}
		}, w).Show()
}

type gitleaksFinding struct {
	RuleID      string   `json:"RuleID"`
	Description string   `json:"Description"`
	File        string   `json:"File"`
	StartLine   int      `json:"StartLine"`
	Secret      string   `json:"Secret"`
	Commit      string   `json:"Commit"`
	Match       string   `json:"Match"`
	Entropy     float64  `json:"Entropy"`
	Tags        []string `json:"Tags"`
}

// generateFindingsHTML: все JSON-отчёты из каталога в одну страницу.
func generateFindingsHTML(dir string) (string, int, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return "", 0, err
	}

	var rows []string
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".json") || strings.HasPrefix(name, "_") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			continue
		}
		var findings []gitleaksFinding
		if json.Unmarshal(data, &findings) != nil {
			continue
		}
		for _, f := range findings {
			rows = append(rows, fmt.Sprintf(
				"<tr><td>%s</td><td>%s</td><td>%s:%d</td>"+
					"<td style='color:#ff5555;word-break:break-all'>%s</td>"+
					"<td>%s</td></tr>",
				html.EscapeString(name),
				html.EscapeString(f.RuleID),
				html.EscapeString(f.File), f.StartLine,
				html.EscapeString(f.Secret),
				html.EscapeString(f.Commit)))
		}
	}

	page := fmt.Sprintf(`<!DOCTYPE html><html><head><meta charset='utf-8'>`+
		`<title>Gitleaks findings</title><style>`+
		`body{background:#111;color:#2ee05a;font-family:monospace;padding:12px}`+
		`table{border-collapse:collapse;width:100%%}`+
		`td,th{border:1px solid #333;padding:4px;font-size:12px;text-align:left}`+
		`th{background:#222;position:sticky;top:0}`+
		`</style></head><body><h1>Gitleaks: %d находок</h1>`+
		`<table><tr><th>отчёт</th><th>правило</th><th>где</th><th>секрет</th><th>коммит</th></tr>%s</table></body></html>`,
		len(rows), strings.Join(rows, ""))

	out := filepath.Join(dir, "_findings.html")
	if err := writeFileAtomic(out, []byte(page)); err != nil {
		return "", 0, err
	}
	return out, len(rows), nil
}

type scanStats struct {
	mu          sync.Mutex
	accounts    int
	accountsOK  int
	repos       int
	cloned      int
	cloneErrors int
	skipped     int
	clean       int
	findings    int
	secrets     int
	errors      int
	started     time.Time
}

// reset обнуляет счётчики, НЕ трогая мьютекс.
// Раньше здесь была полная перезапись `stats = scanStats{...}` — структура
// содержит sync.Mutex, и его перезапись «под ногами» у другой горутины
// была data race.
func (s *scanStats) reset(accounts int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.accounts = accounts
	s.repos = 0
	s.cloned = 0
	s.cloneErrors = 0
	s.skipped = 0
	s.clean = 0
	s.findings = 0
	s.secrets = 0
	s.errors = 0
	s.started = time.Now()
}

// snapshot — согласованный снимок всех счётчиков под одной блокировкой.
func (s *scanStats) snapshot() map[string]int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return map[string]int{
		"Аккаунты":     s.accounts,
		"Репозитории":  s.repos,
		"Склонировано": s.cloned,
		"Ошибки клона": s.cloneErrors,
		"Пропущено":    s.skipped,
		"CLEAN":        s.clean,
		"FINDINGS":     s.findings,
		"Секретов":     s.secrets,
		"Ошибки":       s.errors,
	}
}

func (s *scanStats) elapsed() time.Duration {
	s.mu.Lock()
	defer s.mu.Unlock()
	return time.Since(s.started).Round(time.Second)
}

func parseFindings(path string) int {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	var f []gitleaksFinding
	if json.Unmarshal(data, &f) != nil {
		return 0
	}
	return len(f)
}

func statsBar(bindings map[string]*widget.Label) *fyne.Container {
	order := []string{"Аккаунты", "Репозитории", "Склонировано", "Ошибки клона",
		"Пропущено", "CLEAN", "FINDINGS", "Секретов", "Ошибки"}
	cells := make([]fyne.CanvasObject, 0, len(order))
	for _, k := range order {
		l := widget.NewLabel("0")
		bindings[k] = l
		cells = append(cells, container.NewVBox(
			widget.NewLabel(k),
			l,
		))
	}
	return container.NewGridWithColumns(len(order), cells...)
}

// updateStats: счётчики приходят снаружи — глобального stats больше нет,
// у каждой вкладки свой экземпляр (два параллельных скана не путают цифры).
func updateStats(b map[string]*widget.Label, s *scanStats) {
	v := s.snapshot()
	for k, l := range b {
		l.SetText(fmt.Sprint(v[k]))
	}
}

// ===== Классификация секретов =====

var (
	reHex64   = regexp.MustCompile(`^[0-9a-fA-F]{64}$`)
	reEvmPriv = regexp.MustCompile(`^0x[0-9a-fA-F]{64}$`)
	reWIF     = regexp.MustCompile(`^[5KL][1-9A-HJ-NP-Za-km-z]{49,51}$`)
	reXprv    = regexp.MustCompile(`^(x|t)prv[1-9A-HJ-NP-Za-km-z]{50,}`)
	reToken   = regexp.MustCompile(`^[A-Za-z0-9_\-\.]{32,}$`)
	reCtx     = regexp.MustCompile(`(?i)priv|mnemonic|seed|wallet|keystore|secret|wif`)
	reSVGPath = regexp.MustCompile(`^[Mm][0-9]`)
)

// Известные публичные значения — никогда не «боевые».
var knownPublic = map[string]bool{
	"AckfSECXIvnK5r28GVIWUAxmbBSjTsmF":                                 true,
	"AKIAIOSFODNN7EXAMPLE":                                             true,
	"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY":                         true,
	"ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80": true,
	"4f3edf983ac636a65a842ce7c78d9aa706d3b113bce9c46f30d7d21715b23b1d": true,
}

// junkWords — точные ТОКЕНЫ тестового/демо-пути.
var junkWords = map[string]bool{
	"test": true, "tests": true, "testing": true, "testdata": true,
	"testutils": true, "testcase": true,
	"example": true, "examples": true, "sample": true, "samples": true,
	"demo": true, "demos": true,
	"readme": true, "doc": true, "docs": true,
	"vector": true, "vectors": true,
	"fixture": true, "fixtures": true,
	"benchmark": true, "benchmarks": true,
	"quickstart": true, "conductor": true,
	"travis": true, "workflow": true, "workflows": true,
}

// isDevJunk: путь похож на тестовый/демо — секрет там почти наверняка фейковый.
//
// Сравниваются ТОКЕНЫ (слова, разделённые не-буквенно-цифровыми), а не
// подстроки. Прежняя подстрочная версия давала ложные срабатывания, из-за
// которых НАСТОЯЩИЕ секреты помечались «тест/демо» и не попадали в «боевые»:
//
//	"test" входил в "latest/", "contest/", "attest…"
//	"doc"  входил в "docker-compose.yml", "doctor.go"
func isDevJunk(path string) bool {
	p := strings.ToLower(filepath.ToSlash(path))

	// Расширение бэкапа и пары точных имён — подстрочно, они и так точные.
	if strings.HasSuffix(p, ".bak") || strings.HasSuffix(p, ".bak~") ||
		strings.Contains(p, "play.go") || strings.Contains(p, "docker.local") {
		return true
	}

	// Токены по ВСЕМУ пути: и каталоги (.github/workflows/), и имя файла.
	for _, tok := range strings.FieldsFunc(p, func(r rune) bool {
		return !((r >= 'a' && r <= 'z') || (r >= '0' && r <= '9'))
	}) {
		if junkWords[tok] {
			return true
		}
	}
	return false
}

// ===== Base58Check =====

const b58Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

func b58Payload(s string) (payload []byte, ok bool) {
	num := new(big.Int)
	for _, c := range s {
		i := strings.IndexRune(b58Alphabet, c)
		if i < 0 {
			return nil, false
		}
		num.Mul(num, big.NewInt(58))
		num.Add(num, big.NewInt(int64(i)))
	}
	raw := num.Bytes()
	lead := 0
	for lead < len(s) && s[lead] == '1' {
		lead++
	}
	full := make([]byte, lead+len(raw))
	copy(full[lead:], raw)
	if len(full) < 5 {
		return nil, false
	}
	body, sum := full[:len(full)-4], full[len(full)-4:]
	first := sha256.Sum256(body)
	h := sha256.Sum256(first[:])
	return body, h[0] == sum[0] && h[1] == sum[1] && h[2] == sum[2] && h[3] == sum[3]
}

var (
	verWIF  = []byte{0x80}
	verXprv = []byte{0x04, 0x88, 0xAD, 0xE4}
	verTprv = []byte{0x04, 0x35, 0x83, 0x94}
)

func hasVer(p, ver []byte) bool {
	return len(p) >= len(ver) && bytes.Equal(p[:len(ver)], ver)
}

func validWIF(s string) bool {
	if !reWIF.MatchString(s) {
		return false
	}
	p, ok := b58Payload(s)
	return ok && hasVer(p, verWIF) &&
		(len(p) == 33 || (len(p) == 34 && p[33] == 0x01))
}

func validXprv(s string) bool {
	if !reXprv.MatchString(s) {
		return false
	}
	p, ok := b58Payload(s)
	return ok && len(p) == 78 && p[45] == 0x00 &&
		(hasVer(p, verXprv) || hasVer(p, verTprv))
}

// ===== Seed: кандидат + BIP39-проверка =====

func looksLikeSeed(s string) bool {
	if strings.ContainsAny(s, "\n\r") || strings.Contains(s, "-----BEGIN") {
		return false
	}
	s = strings.ToLower(s)
	words := strings.Fields(s)
	switch len(words) {
	case 12, 15, 18, 21, 24:
	default:
		return false
	}
	for _, w := range words {
		if len(w) < 3 || len(w) > 8 {
			return false
		}
		for _, r := range w {
			if r < 'a' || r > 'z' {
				return false
			}
		}
	}
	return true
}

//go:embed bip39_english.txt
var bip39List string

var bip39Index map[string]int

func init() {
	bip39Index = make(map[string]int, 2048)
	words := strings.Fields(bip39List)
	if len(words) != 2048 {
		fmt.Fprintf(os.Stderr, "warning: bip39_english.txt: %d слов вместо 2048\n", len(words))
	}
	for i, w := range words {
		bip39Index[w] = i
	}
}

func validateBIP39(s string) (wordsOK, checksumOK bool) {
	words := strings.Fields(strings.ToLower(s))
	switch len(words) {
	case 12, 15, 18, 21, 24:
	default:
		return false, false
	}
	idxs := make([]int, len(words))
	for i, w := range words {
		ix, ok := bip39Index[w]
		if !ok {
			return false, false
		}
		idxs[i] = ix
	}
	return true, bip39ChecksumOK(idxs)
}

// bip39ChecksumOK — контрольная сумма BIP39 для готового набора индексов
// слов. Отделена от разбора строки: перебор (bruteForceSeed) зовёт её
// десятки тысяч раз на один вызов и не должен переразбирать строку.
func bip39ChecksumOK(idxs []int) bool {
	n := len(idxs)
	total := n * 11
	cs := total / 33
	entBytes := make([]byte, (total-cs)/8)
	bitAt := func(i int) bool { return idxs[i/11]&(1<<(10-i%11)) != 0 }
	for i := range entBytes {
		for j := 0; j < 8; j++ {
			if bitAt(i*8 + j) {
				entBytes[i] |= 1 << (7 - j)
			}
		}
	}
	h := sha256.Sum256(entBytes)
	for i := 0; i < cs; i++ {
		if bitAt(total-cs+i) != (h[i/8]&(1<<(7-i%8)) != 0) {
			return false
		}
	}
	return true
}

// ===== Перебор: выбитое или испорченное слово =====

// bruteForceSeed восстанавливает фразу, где выбито/испорчено ровно одно слово:
//
//  1. строка длины L (12/15/18/21/24) с ровно одним словом не из словаря —
//     подбираем замену из 2048 слов словаря;
//  2. строка длины L-1 целиком из словаря — вставляем недостающее слово
//     в каждую из L позиций.
//
// Честная оговорка: checksum BIP39 — всего 4..8 бит, поэтому перебор НЕ
// доказывает фразу: при выбитом слове в 12-словной из 2048 кандидатов
// checksum проходит ~128. Функция возвращает ЧИСЛО кандидатов —
// подтверждение только внешнее (проверка баланса кошелька).
func bruteForceSeed(s string) (candidates int, ok bool) {
	words := strings.Fields(strings.ToLower(s))
	n := len(words)
	if n < 11 || n > 24 {
		return 0, false
	}
	// Потолок проверок: максимум для нас — 24 позиции × 2048 слов = 49152.
	const budget = 60_000
	tried := 0
	idxOf := func(w string) (int, bool) { ix, has := bip39Index[w]; return ix, has }

	// 1) длина валидна, ровно одно слово не из словаря -> подбор замены
	switch n {
	case 12, 15, 18, 21, 24:
		bad := -1
		badCnt := 0
		idxs := make([]int, n)
		for i, w := range words {
			ix, has := idxOf(w)
			if has {
				idxs[i] = ix
			} else {
				bad, badCnt = i, badCnt+1
			}
		}
		if badCnt == 1 {
			for wi := 0; wi < 2048 && tried < budget; wi++ {
				tried++
				idxs[bad] = wi
				if bip39ChecksumOK(idxs) {
					candidates++
				}
			}
			return candidates, candidates > 0
		}
		if badCnt > 1 {
			return 0, false // испорчено больше одного слова — перебор не под силу
		}
		return 0, false // все слова из словаря — это другая ветка (checksum/кандидат)
	}

	// 2) длина L-1 и ВСЕ слова из словаря -> подбор недостающего
	miss, has := map[int]int{11: 12, 14: 15, 17: 18, 20: 21, 23: 24}[n]
	if !has {
		return 0, false
	}
	base := make([]int, 0, n)
	for _, w := range words {
		ix, ok := idxOf(w)
		if !ok {
			return 0, false // не всё из словаря — не наш сценарий
		}
		base = append(base, ix)
	}
	cand := make([]int, miss)
	for p := 0; p < miss && tried < budget; p++ {
		j := 0
		for i := 0; i < miss; i++ {
			if i == p {
				continue // сюда подставится кандидат
			}
			cand[i] = base[j]
			j++
		}
		for wi := 0; wi < 2048 && tried < budget; wi++ {
			tried++
			cand[p] = wi
			if bip39ChecksumOK(cand) {
				candidates++
			}
		}
	}
	return candidates, candidates > 0
}

// bruteVerdict — итог перебора: это всегда КАНДИДАТ (checksum не доказывает
// слово при выбитом слове), но с точным числом вариантов для проверки балансом.
func bruteVerdict(s string, junk bool) (class, status string, combat, ok bool) {
	n, found := bruteForceSeed(s)
	if !found {
		return "", "", false, false
	}
	class = "seed-фраза BIP39 (перебор)"
	if junk {
		return class, "тест/демо", false, true
	}
	return class, fmt.Sprintf("перебор: %d кандидатов — проверь балансом", n), false, true
}

// ===== Скрытие: валидная фраза внутри более длинной строки =====

// hiddenSeed снимает самое примитивное сокрытие — дописать/вставить лишние
// слова (12 слов из словаря спрятаны в 15/18/24): контрольная сумма
// считается по каждому окну длины 12/15/18/21/24, а не по всей строке.
// Возвращает позицию первого слова окна и длину окна.
func hiddenSeed(s string) (start, length int, ok bool) {
	words := strings.Fields(strings.ToLower(s))
	if len(words) < 12 {
		return 0, 0, false
	}
	// Потолок длины: gitleaks отдаёт секреты не длиннее 24 слов (regex
	// {11,23}), а для более длинных строк перебор окон стоил бы дорого
	// на каждом вызове verdict() —33k+ вызовов за разборку.
	if len(words) > 64 {
		return 0, 0, false
	}
	// от длинных окон к коротким: если валидно и 15, и вложенное 12 — сообщаем про 15
	for _, n := range []int{24, 21, 18, 15, 12} {
		if len(words) < n {
			continue
		}
		for i := 0; i+n <= len(words); i++ {
			if wOK, csOK := validateBIP39(strings.Join(words[i:i+n], " ")); wOK && csOK {
				return i, n, true
			}
		}
	}
	return 0, 0, false
}

// seedDensity — правило «в группе слов 10 из 20 из словаря B39» (усиленное
// — 20 из 30):1-2 дописанных/пропущенных слова ломают контрольную сумму,
// но словарный состав остаётся. Это КАНДИДАТ, а не доказательство: на
// английской прозе порог 10/20 проходит ~8% окон, поэтому боевым не
// помечается — только «проверь вручную».
func seedDensity(s string) (dict, win int, strong, ok bool) {
	words := strings.Fields(strings.ToLower(s))
	n := len(words)
	if n < 10 {
		return 0, 0, false, false
	}
	if n > 64 { // та же причина потолка, что в hiddenSeed
		return 0, 0, false, false
	}
	countIn := func(w []string) int {
		c := 0
		for _, x := range w {
			if _, in := bip39Index[x]; in {
				c++
			}
		}
		return c
	}
	// окно 20 (для короткой строки — целиком), порог 10
	size := n
	if size > 20 {
		size = 20
	}
	best := 0
	for i := 0; i+size <= n; i++ {
		if c := countIn(words[i : i+size]); c > best {
			best = c
		}
	}
	if best < 10 {
		return 0, 0, false, false
	}
	// усиленное правило 20 из 30:20 словарных слов из всей строки (до 30)
	// либо в окне 30 для более длинных строк
	if n <= 30 {
		strong = countIn(words) >= 20
	} else {
		for i := 0; i+30 <= n; i++ {
			if countIn(words[i:i+30]) >= 20 {
				strong = true
				break
			}
		}
	}
	return best, size, strong, true
}

// hiddenVerdict — валидная BIP39-фраза найдена перебором окон внутри
// более длинной строки (checksum сошёлся — значит, это настоящая фраза).
func hiddenVerdict(start, length int, junk bool) (string, string, bool) {
	if junk {
		return "seed-фраза BIP39 (спрятана)", "тест/демо", false
	}
	return "seed-фраза BIP39 (спрятана)",
		fmt.Sprintf("🔥 похоже на боевой (окно %d слов, позиция %d)", length, start+1), true
}

// ===== Токен: отсекаем SVG-пути и слабые строки =====

func shannon(s string) float64 {
	var cnt [256]int
	for i := 0; i < len(s); i++ {
		cnt[s[i]]++
	}
	var e float64
	n := float64(len(s))
	for _, c := range cnt {
		if c > 0 {
			p := float64(c) / n
			e -= p * math.Log2(p)
		}
	}
	return e
}

func looksLikeToken(s string) bool {
	if reSVGPath.MatchString(s) {
		return false
	}
	var hasDigit, hasAlpha bool
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= '0' && c <= '9':
			hasDigit = true
		case (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'):
			hasAlpha = true
		}
	}
	return hasDigit && hasAlpha && shannon(s) >= 3.5
}

func shapeClass(s string) string {
	if n := len(strings.Fields(s)); n >= 12 && n <= 24 {
		return "много слов (не seed?)"
	}
	low := strings.ToLower(s)
	if strings.Contains(low, "wallet") || strings.Contains(low, "mnemonic") {
		return "wallet-данные"
	}
	if reToken.MatchString(s) && looksLikeToken(s) {
		return "api-key/token"
	}
	return "прочее"
}

// ===== Провайдеры: опознание по формату + живая проверка =====

var liveCheckEnabled atomic.Bool

type secretRule struct {
	name   string
	re     *regexp.Regexp
	combat bool
	check  func(ctx context.Context, s string) (detail string)
}

// probeJSON: тело ответа (до 1КБ) не попадает в лог никогда.
func probeJSON(ctx context.Context, method, url, hdr, val string) (int, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, method, url, nil)
	if err != nil {
		return 0, nil, err
	}
	if hdr != "" {
		req.Header.Set(hdr, val)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
	return resp.StatusCode, body, nil
}

func bearerCheck(url string) func(context.Context, string) string {
	return func(ctx context.Context, s string) string {
		code, _, err := probeJSON(ctx, http.MethodGet, url, "Authorization", "Bearer "+s)
		switch {
		case err != nil:
			return "⚠ сеть — не проверено"
		case code == http.StatusOK:
			return "✅ ЖИВОЙ"
		case code == http.StatusUnauthorized:
			return "❌ мёртвый (401)"
		default:
			return fmt.Sprintf("⚠ HTTP %d — не проверено", code)
		}
	}
}

func ghCheck(ctx context.Context, s string) string {
	code, body, err := probeJSON(ctx, http.MethodGet,
		"https://api.github.com/user", "Authorization", "Bearer "+s)
	if err != nil {
		return "⚠ сеть — не проверено"
	}
	if code == http.StatusOK {
		var u struct {
			Login string `json:"login"`
		}
		if json.Unmarshal(body, &u) == nil && u.Login != "" {
			return "✅ ЖИВОЙ: " + u.Login
		}
		return "✅ ЖИВОЙ"
	}
	if code == http.StatusUnauthorized {
		return "❌ мёртвый (401)"
	}
	return fmt.Sprintf("⚠ HTTP %d — не проверено", code)
}

// Токен Telegram передаётся в URL — штатный механизм их API; в лог не пишем.
func tgCheck(ctx context.Context, s string) string {
	code, body, err := probeJSON(ctx, http.MethodGet,
		"https://api.telegram.org/bot"+s+"/getMe", "", "")
	if err != nil {
		return "⚠ сеть — не проверено"
	}
	if code == http.StatusOK {
		var r struct {
			OK     bool `json:"ok"`
			Result struct {
				Username string `json:"username"`
			} `json:"result"`
		}
		if json.Unmarshal(body, &r) == nil && r.OK && r.Result.Username != "" {
			return "✅ ЖИВОЙ: @" + r.Result.Username
		}
		return "✅ ЖИВОЙ"
	}
	if code == http.StatusUnauthorized {
		return "❌ мёртвый (401)"
	}
	return fmt.Sprintf("⚠ HTTP %d — не проверено", code)
}

func discordCheck(ctx context.Context, s string) string {
	code, _, err := probeJSON(ctx, http.MethodGet,
		"https://discord.com/api/v10/users/@me", "Authorization", "Bot "+s)
	switch {
	case err != nil:
		return "⚠ сеть — не проверено"
	case code == http.StatusOK:
		return "✅ ЖИВОЙ"
	case code == http.StatusUnauthorized:
		return "❌ мёртвый (401)"
	default:
		return fmt.Sprintf("⚠ HTTP %d — не проверено", code)
	}
}

func glCheck(ctx context.Context, s string) string {
	code, _, err := probeJSON(ctx, http.MethodGet,
		"https://gitlab.com/api/v4/user", "PRIVATE-TOKEN", s)
	switch {
	case err != nil:
		return "⚠ сеть — не проверено"
	case code == http.StatusOK:
		return "✅ ЖИВОЙ"
	case code == http.StatusUnauthorized:
		return "❌ мёртвый (401)"
	default:
		return fmt.Sprintf("⚠ HTTP %d — не проверено", code)
	}
}

func slackCheck(ctx context.Context, s string) string {
	_, body, err := probeJSON(ctx, http.MethodPost,
		"https://slack.com/api/auth.test", "Authorization", "Bearer "+s)
	if err != nil {
		return "⚠ сеть — не проверено"
	}
	var r struct {
		OK    bool   `json:"ok"`
		Error string `json:"error"`
		Team  string `json:"team"`
	}
	_ = json.Unmarshal(body, &r)
	switch {
	case r.OK:
		if r.Team != "" {
			return "✅ ЖИВОЙ: " + r.Team
		}
		return "✅ ЖИВОЙ"
	case r.Error == "invalid_auth" || r.Error == "account_inactive" || r.Error == "token_revoked":
		return "❌ мёртвый (" + r.Error + ")"
	default:
		return "⚠ не проверено"
	}
}

func googleCheck(ctx context.Context, s string) string {
	code, body, err := probeJSON(ctx, http.MethodGet,
		"https://generativelanguage.googleapis.com/v1beta/models", "x-goog-api-key", s)
	if err != nil {
		return "⚠ сеть — не проверено"
	}
	switch {
	case code == http.StatusOK:
		return "✅ ЖИВОЙ"
	case code == http.StatusBadRequest && strings.Contains(string(body), "API key not valid"):
		return "❌ мёртвый"
	default:
		return fmt.Sprintf("⚠ HTTP %d — не проверено", code)
	}
}

func antCheck(ctx context.Context, s string) string {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		"https://api.anthropic.com/v1/models", nil)
	if err != nil {
		return "⚠ не проверено"
	}
	req.Header.Set("x-api-key", s)
	req.Header.Set("anthropic-version", "2023-06-01")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "⚠ сеть — не проверено"
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
		return "✅ ЖИВОЙ"
	case http.StatusUnauthorized:
		return "❌ мёртвый (401)"
	default:
		return fmt.Sprintf("⚠ HTTP %d — не проверено", resp.StatusCode)
	}
}

// Порядок важен: узкие правила раньше широких (sk-ant- до sk-).
var secretRules = []secretRule{
	{"Anthropic API key", regexp.MustCompile(`^sk-ant-[A-Za-z0-9_-]{24,}$`), true, antCheck},
	{"OpenAI API key", regexp.MustCompile(`^sk-(proj-)?[A-Za-z0-9_-]{20,}$`), true,
		bearerCheck("https://api.openai.com/v1/models")},
	{"GitHub PAT (классический)", regexp.MustCompile(`^ghp_[A-Za-z0-9]{36}$`), true, ghCheck},
	{"GitHub PAT (fine-grained)", regexp.MustCompile(`^github_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59}$`), true, ghCheck},
	{"GitHub OAuth/app token", regexp.MustCompile(`^gh[os]_[A-Za-z0-9]{36}$`), true, ghCheck},
	{"GitHub user/refresh token", regexp.MustCompile(`^gh[ur]_[A-Za-z0-9]{36}$`), false, nil},
	{"GitLab PAT", regexp.MustCompile(`^glpat-[A-Za-z0-9_-]{20,}$`), true, glCheck},
	{"Telegram bot token", regexp.MustCompile(`^\d{8,10}:AA[A-Za-z0-9_-]{33}$`), true, tgCheck},
	{"Discord bot token", regexp.MustCompile(`^[A-Za-z0-9_-]{24}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27}$`), true, discordCheck},
	{"Slack token", regexp.MustCompile(`^xox[abprs]-[A-Za-z0-9-]{10,}$`), true, slackCheck},
	{"Google API key", regexp.MustCompile(`^AIza[0-9A-Za-z_-]{35}$`), true, googleCheck},
	{"Stripe secret key", regexp.MustCompile(`^[sr]k_live_[A-Za-z0-9]{16,}$`), true,
		bearerCheck("https://api.stripe.com/v1/charges?limit=1")},
	{"SendGrid API key", regexp.MustCompile(`^SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}$`), true,
		bearerCheck("https://api.sendgrid.com/v3/scopes")},
	{"AWS Access Key ID", regexp.MustCompile(`^AKIA[0-9A-Z]{16}$`), true, nil},
	{"npm token", regexp.MustCompile(`^npm_[A-Za-z0-9]{36}$`), true,
		bearerCheck("https://registry.npmjs.org/-/user/npm.whoami")},
	{"JWT-токен", regexp.MustCompile(`^eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$`), false, nil},
}

func matchSecretRule(s string) *secretRule {
	for i := range secretRules {
		if secretRules[i].re.MatchString(s) {
			return &secretRules[i]
		}
	}
	return nil
}

// verdict — главный вердикт по находке (spread = в скольких репо встречается).
func verdict(f gitleaksFinding, spread int) (class, status string, combat bool) {
	s := strings.TrimSpace(f.Secret)
	junk := isDevJunk(f.File)

	if knownPublic[s] {
		return shapeClass(s), "публичный пример", false
	}

	// Перебор окон: валидная фраза может быть спрятана среди лишних слов.
	hidStart, hidLen, hidOK := hiddenSeed(s)

	switch {
	case validWIF(s):
		if junk {
			return "WIF BTC (валид.)", "тест/демо", false
		}
		return "WIF BTC (валид.)", "🔥 похоже на боевой", true
	case reWIF.MatchString(s):
		return "WIF BTC (формат?)", "checksum не сошёлся", false
	case validXprv(s):
		if junk {
			return "xprv HD (валид.)", "тест/демо", false
		}
		return "xprv HD (валид.)", "🔥 похоже на боевой", true
	case reXprv.MatchString(s):
		return "xprv (формат?)", "checksum не сошёлся", false
	case looksLikeSeed(s):
		wOK, csOK := validateBIP39(s)
		switch {
		case wOK && csOK && !junk:
			return "seed-фраза BIP39 (валид.)", "🔥 похоже на боевой", true
		case wOK && csOK:
			return "seed-фраза BIP39 (валид.)", "тест/демо", false
		case hidOK:
			// вся строка не сходится, но внутри спрятано валидное окно
			return hiddenVerdict(hidStart, hidLen, junk)
		case wOK:
			return "слова BIP39", "checksum не сошёлся", false
		default:
			// ровно одно слово выбито/испорчено — пробуем подобрать замену
			if cls, st, cb, bok := bruteVerdict(s, junk); bok {
				return cls, st, cb
			}
			return "seed-фраза (кандидат)", "проверь вручную", false
		}
	case reHex64.MatchString(s) && reCtx.MatchString(f.Match):
		if junk {
			return "hex64-ключ (priv-контекст)", "тест/демо", false
		}
		return "hex64-ключ (priv-контекст)", "🔥 похоже на боевой", true
	case reEvmPriv.MatchString(s) && reCtx.MatchString(f.Match):
		if junk {
			return "EVM-ключ 0x (priv-контекст)", "тест/демо", false
		}
		return "EVM-ключ 0x (priv-контекст)", "🔥 похоже на боевой", true
	case reEvmPriv.MatchString(s):
		return "0x-данные (хеш?)", "—", false
	case reHex64.MatchString(s):
		return "hex64 (хеш?)", "—", false
	}

	// Формат опознан по таблице провайдеров.
	if rule := matchSecretRule(s); rule != nil {
		if junk {
			return rule.name, "тест/демо", false
		}
		if rule.combat {
			return rule.name, "🔥 формат опознан", true
		}
		return rule.name, "—", false
	}

	// Фраза нестандартной длины (13/14/16… слов), но внутри спрятано
	// валидное окно — контрольная сумма сошлась, значит настоящая.
	if hidOK {
		return hiddenVerdict(hidStart, hidLen, junk)
	}

	// Пропало ровно одно слово (длина L-1: 11/14/17/20/23) — перебором
	// подставляем недостающее и считаем, сколько вариантов проходит checksum.
	if cls, st, cb, bok := bruteVerdict(s, junk); bok {
		return cls, st, cb
	}

	// Плотность словаря B39 (10 из 20 / 20 из 30): фразу могли
	// дописать или порезать, checksum уже не сходится — кандидат.
	if dict, win, strong, ok := seedDensity(s); ok {
		class := "seed-фраза (кандидат 10/20)"
		status := fmt.Sprintf("словарь %d/%d — проверь вручную", dict, win)
		if strong {
			class = "seed-фраза (кандидат 20/30)"
			status = fmt.Sprintf("словарь %d/%d — почти наверняка", dict, win)
		}
		if junk {
			return class, "тест/демо", false
		}
		return class, status, false
	}

	if spread >= 3 {
		return shapeClass(s), fmt.Sprintf("шаблон (в %d репо)", spread), false
	}
	if junk {
		return shapeClass(s), "тест/демо", false
	}
	return shapeClass(s), "—", false
}

// generateBreakdownHTML: группировка по репо; дубли секрета внутри репо
// схлопываются в «×N копий»; боевым известным ключам — живая проверка.
func generateBreakdownHTML(dir string) (path string, nRepos, nFindings, nReal int, err error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return "", 0, 0, 0, err
	}

	// Живые проверки: общий лимит времени и кэш по секрету.
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	liveCache := map[string]string{}
	liveChecks := 0

	// Имя отчёта: account__repo__timestamp.json. Оставляем самый свежий
	// на каждую пару аккаунт+репозиторий (имена отсортированы — последний и есть свежий).
	latest := map[string]string{}
	order := []string{}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".json") || strings.HasPrefix(name, "_") {
			continue
		}
		parts := strings.Split(strings.TrimSuffix(name, ".json"), "__")
		if len(parts) < 2 {
			continue
		}
		key := parts[0] + "__" + parts[1]
		if _, ok := latest[key]; !ok {
			order = append(order, key)
		}
		latest[key] = name
	}

	type repoInfo struct {
		rules map[string]int
		items []gitleaksFinding
		cands map[string][]gitleaksFinding // все копии секрета в этом репо
		dups  map[string]int               // секрет -> сколько копий схлопнуто
	}
	repos := map[string]*repoInfo{}
	seen := map[string]bool{}
	spread := map[string]map[string]bool{} // секрет -> репо, где встречается

	for _, key := range order {
		data, err := os.ReadFile(filepath.Join(dir, latest[key]))
		if err != nil {
			continue
		}
		var fs []gitleaksFinding
		if json.Unmarshal(data, &fs) != nil {
			continue
		}
		r := repos[key]
		if r == nil {
			r = &repoInfo{
				rules: map[string]int{},
				cands: map[string][]gitleaksFinding{},
				dups:  map[string]int{},
			}
			repos[key] = r
		}
		for _, f := range fs {
			sec := strings.TrimSpace(f.Secret)
			if sec == "" {
				continue
			}
			// spread — по всем сырым находкам: сколько РАЗНЫХ репо встречают секрет.
			if spread[sec] == nil {
				spread[sec] = map[string]bool{}
			}
			spread[sec][key] = true

			sig := key + "|" + f.File + "|" + strconv.Itoa(f.StartLine) + "|" + sec
			if seen[sig] {
				continue
			}
			seen[sig] = true
			r.cands[sec] = append(r.cands[sec], f)
		}

		// Один представитель на секрет: предпочитаем копию не из тестового пути.
		for sec, list := range r.cands {
			best := list[0]
			for _, f := range list[1:] {
				if isDevJunk(best.File) && !isDevJunk(f.File) {
					best = f
				}
			}
			r.items = append(r.items, best)
			r.rules[best.RuleID]++
			if len(list) > 1 {
				r.dups[sec] = len(list) - 1
			}
		}
		// Порядок строк как в исходном отчёте.
		sort.SliceStable(r.items, func(i, j int) bool {
			if r.items[i].File != r.items[j].File {
				return r.items[i].File < r.items[j].File
			}
			return r.items[i].StartLine < r.items[j].StartLine
		})
	}

	var b strings.Builder
	b.WriteString(`<!DOCTYPE html><html><head><meta charset='utf-8'><title>Разборка секретов</title><style>` +
		`body{background:#111;color:#2ee05a;font-family:monospace;padding:12px}` +
		`summary{cursor:pointer;font-size:15px;padding:4px}` +
		`table{border-collapse:collapse;width:100%;margin:8px 0}` +
		`td,th{border:1px solid #333;padding:3px 6px;font-size:12px;text-align:left}` +
		`th{background:#222}</style></head><body><h1>Разборка всех секретов</h1>`)

	keys := make([]string, 0, len(repos))
	for k := range repos {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, key := range keys {
		r := repos[key]
		findings := len(r.items)

		type row struct {
			class, file, secret, status string
			line                        int
			combat, junk                bool
		}
		rows := make([]row, 0, len(r.items))
		real := 0
		for _, f := range r.items {
			sec := strings.TrimSpace(f.Secret)
			class, status, combat := verdict(f, len(spread[sec]))
			if n := r.dups[sec]; n > 0 {
				status += fmt.Sprintf(" ×%d копий в репо", n+1)
			}
			// Живая проверка: только для «боевых» с известным провайдером,
			// по галке в GUI, не более 25 уникальных секретов за разборку.
			if rule := matchSecretRule(sec); rule != nil && rule.check != nil &&
				combat && liveCheckEnabled.Load() && ctx.Err() == nil {
				if c, ok := liveCache[sec]; ok {
					status += c
				} else if liveChecks < 25 {
					liveChecks++
					detail := rule.check(ctx, sec)
					liveCache[sec] = " | " + detail
					status += " | " + detail
				}
			}
			rows = append(rows, row{
				class: class, file: f.File, line: f.StartLine,
				secret: sec, status: status,
				combat: combat, junk: isDevJunk(f.File),
			})
			if combat {
				real++
			}
		}
		nRepos++
		nFindings += findings
		nReal += real

		// Валидные кандидаты — вверх, мусор — вниз.
		sort.SliceStable(rows, func(i, j int) bool {
			if rows[i].combat != rows[j].combat {
				return rows[i].combat
			}
			return !rows[i].junk && rows[j].junk
		})

		rules := make([]string, 0, len(r.rules))
		for k, v := range r.rules {
			rules = append(rules, fmt.Sprintf("%s: %d", k, v))
		}
		sort.Strings(rules)

		badge := ""
		if real > 0 {
			badge = fmt.Sprintf(" <span style='color:#ff5555'>🔥%d похожих на боевые</span>", real)
		}
		// Секции с находками раскрыты по умолчанию: иначе в браузере видны
		// лишь строки открытых вручную репо, а «свёрнуто» читается как «пусто».
		fmt.Fprintf(&b, "<details %s><summary><b>%s</b> — %d находок%s</summary>",
			boolAttr(findings > 0), html.EscapeString(key), findings, badge)
		fmt.Fprintf(&b, "<p>Правила: %s</p><table><tr><th>класс</th><th>файл:строка</th><th>секрет</th><th>статус</th></tr>",
			html.EscapeString(strings.Join(rules, ", ")))

		// Лимита на число строк нет: в отчёт попадает каждый секрет,
		// сколько бы их ни было (проверялось на 43k находок в одном репо).
		for _, it := range rows {
			color := "#ffa51a"
			switch {
			case it.combat:
				color = "#ff5555"
			case it.junk || it.status == "тест/демо" || it.status == "публичный пример" ||
				strings.HasPrefix(it.status, "шаблон"):
				color = "#cccccc"
			}
			fmt.Fprintf(&b, "<tr><td style='color:%s'>%s</td><td>%s:%d</td>"+
				"<td style='word-break:break-all'>%s</td><td>%s</td></tr>",
				color, html.EscapeString(it.class), html.EscapeString(it.file),
				it.line, html.EscapeString(it.secret), html.EscapeString(it.status))
		}
		b.WriteString("</table></details>")
	}

	fmt.Fprintf(&b, "<p>Репозиториев: %d | находок: %d | похожих на боевые: %d</p></body></html>",
		nRepos, nFindings, nReal)

	out := filepath.Join(dir, "_breakdown.html")
	if err := writeFileAtomic(out, []byte(b.String())); err != nil {
		return "", 0, 0, 0, err
	}
	return out, nRepos, nFindings, nReal, nil
}

// runAsync запускает генерацию отчёта в фоне и не даёт запустить вторую
// копию, пока первая не закончила. Нужно потому, что generateBreakdownHTML
// при включённой галке «Проверять ключи онлайн» делает до 25 HTTP-запросов
// в контексте на 3 минуты — синхронный вызов из обработчика кнопки
// намертво замораживал окно Fyne.
func runAsync(log *logView, busy *atomic.Bool, what string, fn func()) {
	if !busy.CompareAndSwap(false, true) {
		log.append("[WARN] %s ещё формируется — подожди", what)
		return
	}
	go func() {
		defer busy.Store(false)
		fn()
	}()
}

// writeFileAtomic: пишем в уникальный временный файл рядом и переименовываем.
// Браузер, открытый сразу после генерации, не поймает обрезанную страницу,
// а два параллельных вызова не перетрут чужой временный файл (поэтому
// имя — через os.CreateTemp, а не фиксированный path+".tmp").
func writeFileAtomic(path string, data []byte) error {
	dir, base := filepath.Split(path)
	if dir == "" {
		dir = "."
	}
	tmp, err := os.CreateTemp(dir, "."+base+".tmp")
	if err != nil {
		return err
	}
	name := tmp.Name()
	cleanup := func() {
		_ = tmp.Close()
		_ = os.Remove(name)
	}

	if _, err := tmp.Write(data); err != nil {
		cleanup()
		return err
	}
	// os.CreateTemp даёт 0600 — возвращаем прежние 0644.
	_ = os.Chmod(name, 0o644)
	if err := tmp.Close(); err != nil {
		_ = os.Remove(name)
		return err
	}
	if err := os.Rename(name, path); err != nil {
		_ = os.Remove(name)
		return err
	}
	return nil
}

func boolAttr(b bool) string {
	if b {
		return "open"
	}
	return ""
}

// ===== Вкладка 1: сканер репозиториев =====

func scannerTab(w fyne.Window, token *widget.Entry, fileEntry *widget.Entry, scanTrigger *widget.Button) fyne.CanvasObject {
	log := newLogView()
	bindings := map[string]*widget.Label{}
	bar := statsBar(bindings)
	stats := &scanStats{} // счётчики ТОЛЬКО этой вкладки
	// Фоновые генерации отчётов (см. runAsync): одна кнопка — один запуск.
	var reportBusy, breakdownBusy, aiBusy atomic.Bool

	selectFile := widget.NewButton("Выбрать файл", func() {
		dialog.ShowFileOpen(func(r fyne.URIReadCloser, err error) {
			if err != nil || r == nil {
				return
			}
			fileEntry.SetText(r.URI().Path())
			r.Close()
		}, w)
	})

	start := widget.NewButton("START", nil)
	stop := widget.NewButton("STOP", nil)
	save := widget.NewButton("SAVE LOG", nil)
	clear := widget.NewButton("CLEAR", func() { log.clear() })

	scanner := &Scanner{}
	stop.Disable()

	startScan := func() {
		scanner.mu.Lock()
		if scanner.running {
			scanner.mu.Unlock()
			return
		}

		tok := strings.TrimSpace(token.Text)
		file := strings.TrimSpace(fileEntry.Text)

		if tok == "" {
			scanner.mu.Unlock()
			dialog.ShowInformation("Ошибка", "Укажи GitHub Token.", w)
			return
		}
		if file == "" {
			scanner.mu.Unlock()
			dialog.ShowInformation("Ошибка", "Выбери accounts.txt.", w)
			return
		}

		data, err := os.Open(file)
		if err != nil {
			scanner.mu.Unlock()
			dialog.ShowError(err, w)
			return
		}

		var users []string
		sc := bufio.NewScanner(data)
		for sc.Scan() {
			u := strings.TrimSpace(sc.Text())
			if u != "" && !strings.HasPrefix(u, "#") {
				users = append(users, u)
			}
		}
		data.Close()

		if err := sc.Err(); err != nil {
			scanner.mu.Unlock()
			dialog.ShowError(err, w)
			return
		}
		if len(users) == 0 {
			scanner.mu.Unlock()
			dialog.ShowInformation("Файл пуст",
				"В accounts.txt нет ни одного аккаунта.\n"+
					"Добавь логины или собери их на вкладке «Сбор аккаунтов».", w)
			return
		}

		gitleaksPath, gerr := findTool("gitleaks")
		if gerr != nil {
			scanner.mu.Unlock()
			dialog.ShowInformation("gitleaks не найден",
				"Установи gitleaks (например: go install github.com/gitleaks/gitleaks/v8@latest)\n"+
					"и убедись, что ~/go/bin в PATH.", w)
			return
		}

		if err := os.MkdirAll(reportsDir(), 0o755); err != nil {
			scanner.mu.Unlock()
			dialog.ShowError(err, w)
			return
		}

		ctx, cancel := context.WithCancel(context.Background())
		scanner.cancel = cancel
		scanner.running = true
		scanner.mu.Unlock()

		start.Disable()
		stop.Enable()

		// Счётчик ставим ДО старта горутины: иначе клик «ОЧИСТИТЬ» между
		// нажатием START и планированием горутины успевает удалить только что
		// созданную папку скана.
		activeScans.Add(1)

		go func() {
			wake := keepAwake("идёт сканирование репозиториев")
			defer wake()
			defer activeScans.Add(-1)

			// Папка ТОЛЬКО этого скана: все отчёты пишем туда.
			sd := newScanDir()

			defer func() {
				scanner.mu.Lock()
				scanner.running = false
				scanner.cancel = nil
				scanner.mu.Unlock()

				start.Enable()
				stop.Disable()
				snap := stats.snapshot() // без блокировки чтение запрещено
				log.append("Итог: FINDINGS=%d CLEAN=%d секретов=%d за %s",
					snap["FINDINGS"], snap["CLEAN"], snap["Секретов"], stats.elapsed())

				// Автоматическая разборка секретов по принадлежности.
				if bp, nr, nf, nreal, berr := generateBreakdownHTML(sd); berr == nil {
					log.append("Разборка обновлена: %d репо, %d находок, похожих на боевые: %d", nr, nf, nreal)
					log.append("Открыть: %s", bp)
				}
				log.append("=== СКАНИРОВАНИЕ ЗАВЕРШЕНО ===")
			}()

			log.append("=== GitHub Gitleaks Scanner ===")
			log.append("Папка скана: %s", sd)

			stats.reset(len(users))
			fyne.Do(func() { updateStats(bindings, stats) })

			for _, user := range users {
				if ctx.Err() != nil {
					log.append("Остановлено пользователем.")
					return
				}

				log.append("")
				log.append("[ACCOUNT] %s", user)

				repos, err := githubRepos(ctx, tok, user)
				if err != nil {
					log.append("[ERROR] %s: %v", user, err)
					continue
				}

				log.append("[REPOS] %d", len(repos))

				stats.mu.Lock()
				stats.repos += len(repos)
				stats.mu.Unlock()
				fyne.Do(func() { updateStats(bindings, stats) })

				for _, repo := range repos {
					if ctx.Err() != nil {
						log.append("Остановлено пользователем.")
						return
					}

					// Фильтр по размеру: гигантские репо клонируются
					// минутами и вешают gitleaks на git log -p всей истории.
					if repo.Size > maxRepoSizeKB {
						log.append("[SKIP] %s: %d МБ > лимита %d МБ",
							repo.Name, repo.Size/1024, maxRepoSizeKB/1024)
						stats.mu.Lock()
						stats.skipped++
						stats.mu.Unlock()
						fyne.Do(func() { updateStats(bindings, stats) })
						continue
					}

					safeUser := strings.ReplaceAll(user, "/", "_")
					safeRepo := strings.ReplaceAll(repo.Name, "/", "_")
					work := filepath.Join(os.TempDir(),
						"github-scanner-"+safeUser+"-"+safeRepo)

					_ = os.RemoveAll(work)

					log.append("[CLONE] %s", repo.Name)

					askpass := filepath.Join(work + "-askpass")
					if err := os.WriteFile(askpass,
						[]byte("#!/bin/sh\nprintf '%s\\n' \"$GITHUB_TOKEN\"\n"),
						0700); err != nil {
						log.append("[ERROR] askpass: %v", err)
						continue
					}

					cloneDir := work

					// Таймаут клона: без него зависший git держал скан вечно.
					cloneCtx, cloneCancel := context.WithTimeout(ctx, cloneTimeout)
					cloneCmd := exec.CommandContext(cloneCtx, "git",
						"clone", "--mirror", repo.CloneURL, cloneDir)
					cloneCmd.Env = append(os.Environ(),
						"GIT_TERMINAL_PROMPT=0",
						"GITHUB_TOKEN="+tok,
						"GIT_ASKPASS="+askpass,
					)
					cloneCmd.Stderr = os.Stderr
					err = cloneCmd.Run()
					cloneCancel()
					_ = os.Remove(askpass)

					if err != nil {
						if cloneCtx.Err() == context.DeadlineExceeded {
							log.append("[CLONE TIMEOUT] %s:>%s", repo.Name, cloneTimeout)
						} else {
							log.append("[CLONE ERROR] %s", repo.Name)
						}
						stats.mu.Lock()
						stats.cloneErrors++
						stats.mu.Unlock()
						fyne.Do(func() { updateStats(bindings, stats) })
						_ = os.RemoveAll(work)
						continue
					}

					stats.mu.Lock()
					stats.cloned++
					stats.mu.Unlock()

					reportName := safeUser + "__" + safeRepo + "__" +
						time.Now().Format("20060102_150405") + ".json"
					report := filepath.Join(sd, reportName)

					log.append("[GITLEAKS] %s", repo.Name)

					var gitleaksPid atomic.Int64
					pulseStop := make(chan struct{})
					pulseDone := make(chan struct{})
					go func() {
						defer close(pulseDone)
						for i := 0; i < 40 && gitleaksPid.Load() == 0; i++ {
							select {
							case <-pulseStop:
								return
							case <-time.After(100 * time.Millisecond):
							}
						}
						if gitleaksPid.Load() == 0 {
							return
						}
						procPulse(pulseStop, pulseDone, int(gitleaksPid.Load()), cloneDir, log, 15*time.Second)
					}()

					// Таймаут gitleaks: git log -p по всей истории большого
					// репо мог идти часами — теперь репо отбрасывается.
					leakCtx, leakCancel := context.WithTimeout(ctx, gitleaksTout)
					// nice: gitleaks ест 1+ ядра целиком — интерфейс и система
					// не должны страдать во время скана (nice делает exec,
					// pid не меняется — procPulse продолжает работать).
					leakArgs := append([]string{"-n", "10", gitleaksPath, "git", cloneDir,
						"--report-format", "json",
						"--report-path", report},
						gitleaksConfigArgs()...)
					_, code, err := runCommandStream(leakCtx, ".", func(line string) {
						if strings.Contains(line, "commits scanned") ||
							strings.Contains(line, "scanned ~") ||
							strings.Contains(line, "leaks found") ||
							strings.Contains(line, "no leaks") ||
							strings.Contains(line, "scan in progress") ||
							strings.Contains(line, "Emoji") || strings.Contains(line, "commits") {
							clean := stripANSI(strings.TrimSpace(line))
							if clean != "" {
								log.append("    %s", clean)
							}
						}
					}, func(pid int) { gitleaksPid.Store(int64(pid)) },
						"nice", leakArgs...,
					)
					leakTimedOut := leakCtx.Err() == context.DeadlineExceeded
					leakCancel()
					close(pulseStop)

					if err != nil && ctx.Err() != nil {
						_ = os.RemoveAll(work)
						log.append("Остановлено пользователем.")
						return
					}
					if leakTimedOut {
						log.append("[GITLEAKS TIMEOUT] %s: >%s, репо пропущено", repo.Name, gitleaksTout)
						stats.mu.Lock()
						stats.errors++
						stats.mu.Unlock()
						fyne.Do(func() { updateStats(bindings, stats) })
						_ = os.RemoveAll(work)
						continue
					}
					if err != nil {
						log.append("[WARN] %s: вывод gitleaks неполный: %v", repo.Name, err)
					}

					if code == 0 {
						log.append("[CLEAN] %s", repo.Name)
						stats.mu.Lock()
						stats.clean++
						stats.mu.Unlock()
					} else if code == 1 {
						n := parseFindings(report)
						log.append("[FINDINGS] %s (%d секретов) -> %s", repo.Name, n, report)
						stats.mu.Lock()
						stats.findings++
						stats.secrets += n
						stats.mu.Unlock()
					} else {
						log.append("[GITLEAKS ERROR] %s (exit %d)", repo.Name, code)
						stats.mu.Lock()
						stats.errors++
						stats.mu.Unlock()
					}
					fyne.Do(func() { updateStats(bindings, stats) })

					_ = os.RemoveAll(work)
				}
			}
		}()
	}

	start.OnTapped = startScan
	scanTrigger.OnTapped = startScan

	stop.OnTapped = func() {
		log.append("Запрошена остановка...")
		scanner.stop()
	}

	save.OnTapped = func() {
		dialog.ShowFileSave(func(wc fyne.URIWriteCloser, err error) {
			if err != nil || wc == nil {
				return
			}
			defer wc.Close()
			_, _ = wc.Write([]byte(log.text()))
			log.append("Лог сохранён: %s", wc.URI().Path())
		}, w)
	}

	// ОТЧЁТ HTML: находки последнего скана в одну страницу.
	report := widget.NewButton("ОТЧЁТ HTML", func() {
		runAsync(log, &reportBusy, "отчёт", func() {
			dir := pickScanDir()
			path, n, err := generateFindingsHTML(dir)
			if err != nil {
				log.append("[ERROR] отчёт: %v", err)
				return
			}
			log.append("Отчёт: %s (%d находок) — открываю браузер...", path, n)
			openBrowser(path)
		})
	})

	// РАЗБОРКА: группирует секреты по принадлежности (аккаунт → репо → класс).
	// Один флаг на обе кнопки: обе пишут один и тот же _breakdown.html.
	breakdown := widget.NewButton("РАЗБОРКА", func() {
		runAsync(log, &breakdownBusy, "разборка", func() {
			dir := pickScanDir()
			path, nr, nf, nreal, err := generateBreakdownHTML(dir)
			if err != nil {
				log.append("[ERROR] разборка: %v", err)
				return
			}
			log.append("Разборка: %d репо, %d находок, похожих на боевые: %d — %s", nr, nf, nreal, path)
			openBrowser(path)
		})
	})

	// Последний скан: разборка самой свежей папки scan_*.
	openLast := widget.NewButton("ПОСЛЕДНИЙ СКАН", func() {
		runAsync(log, &breakdownBusy, "разборка", func() {
			dir := pickScanDir()
			path, nr, nf, nreal, err := generateBreakdownHTML(dir)
			if err != nil {
				log.append("[ERROR] разборка: %v", err)
				return
			}
			log.append("Последний скан: %s — %d репо, %d находок, боевых: %d", dir, nr, nf, nreal)
			openBrowser(path)
		})
	})

	// Открыть папку последнего скана в файловом менеджере.
	openDir := widget.NewButton("ОТКРЫТЬ ПАПКУ", func() {
		dir := pickScanDir()
		if err := openFolder(dir); err != nil {
			log.append("[ERROR] открыть папку: %v", err)
			return
		}
		log.append("Открываю папку: %s", dir)
	})

	// Очистка папки результатов (с подтверждением, запрещена во время скана).
	clearAll := widget.NewButton("ОЧИСТИТЬ", func() { clearReports(w, log, fileEntry) })

	// AI-разбор: окно выбора провайдера (Groq/DeepSeek/Gemini/OpenRouter)
	// + ключ, потом ai_verdict.py ранжирует находки REAL/FAKE.
	aiRun := widget.NewButton("AI-РАЗБОР", func() {
		prefs := fyne.CurrentApp().Preferences()
		provSel := widget.NewSelect([]string{"groq", "openrouter", "deepseek", "gemini"}, nil)
		provSel.SetSelected(prefs.StringWithFallback("ai_provider", "groq"))
		keyEntry := widget.NewPasswordEntry()
		keyEntry.SetPlaceHolder("API-ключ провайдера (пусто = из preferences)")
		keyEntry.SetText(prefs.StringWithFallback("ai_key_"+provSel.Selected, ""))
		provSel.OnChanged = func(s string) {
			keyEntry.SetText(prefs.StringWithFallback("ai_key_"+s, ""))
		}
		box := container.NewVBox(
			widget.NewLabel("Провайдер LLM:"), provSel,
			widget.NewLabel("API-ключ:"), keyEntry,
			widget.NewLabel("Groq/OpenRouter — бесплатно; DeepSeek/Gemini — free tier."),
		)
		dialog.NewCustomConfirm("AI-разбор находок", "ЗАПУСТИТЬ", "Отмена", box,
			func(ok bool) {
				if !ok {
					return
				}
				prov := provSel.Selected
				if prov == "" {
					prov = "groq"
				}
				key := strings.TrimSpace(keyEntry.Text)
				prefs.SetString("ai_provider", prov)
				if key != "" {
					prefs.SetString("ai_key_"+prov, key)
				}
				dir := pickScanDir()
				runAsync(log, &aiBusy, "AI-разбор", func() {
					py, perr := exec.LookPath("python3")
					if perr != nil {
						log.append("[ERROR] python3 не найден: %v", perr)
						return
					}
					log.append("[AI] провайдер=%s, папка=%s", prov, dir)
					args := []string{filepath.Join(exeDir(), "ai_verdict.py"),
						"--dir", dir, "--provider", prov}
					if key != "" {
						args = append(args, "--key", key)
					}
					_, code, err := runCommandStream(context.Background(), ".",
						func(line string) { log.append("    %s", line) }, nil,
						py, args...)
					if err != nil {
						log.append("[AI ERROR] %v", err)
					}
					if code != 0 {
						log.append("[AI ERROR] exit %d", code)
						return
					}
					out := filepath.Join(dir, "_ai_verdict.html")
					log.append("[AI] вердикт готов: %s", out)
					openBrowser(out)
				})
			}, w).Show()
	})

	// Онлайн-проверка ключей: разборка будет спрашивать API провайдеров.
	liveCheck := widget.NewCheck("Проверять ключи онлайн", func(b bool) {
		liveCheckEnabled.Store(b)
	})

	return container.NewBorder(
		container.NewVBox(
			widget.NewLabel("Accounts file"),
			container.NewBorder(nil, nil, nil, selectFile, fileEntry),
			container.NewHBox(start, stop, save, clear, report, breakdown, openLast, openDir, clearAll, aiRun, liveCheck),
			widget.NewLabel("Статистика прогона"),
			bar,
		),
		widget.NewLabel(""),
		nil, nil,
		log.widget(),
	)
}

// ===== Вкладка 2: сбор аккаунтов =====

func collectorTab(w fyne.Window, token *widget.Entry, fileEntry *widget.Entry, onCollected func(outPath string)) fyne.CanvasObject {
	topicsEntry := widget.NewEntry()
	topicsEntry.SetPlaceHolder("Темы через запятую: crypto, solidity")

	langsEntry := widget.NewEntry()
	langsEntry.SetPlaceHolder("Языки через запятую (пусто = любые): go, rust")

	orgsCheck := widget.NewCheck("Оставлять только организации", nil)

	minStarsEntry := widget.NewEntry()
	minStarsEntry.SetPlaceHolder("0")
	minStarsEntry.SetText("0")

	maxEntry := widget.NewEntry()
	maxEntry.SetPlaceHolder("0 = без лимита")
	maxEntry.SetText("0")

	outEntry := widget.NewEntry()
	outEntry.SetPlaceHolder("Куда сохранить (пусто = accounts.txt рядом с программой)")
	outEntry.SetText("accounts.txt")

	log := newLogView()

	selectOut := widget.NewButton("Выбрать файл", func() {
		dialog.NewFileSave(func(wc fyne.URIWriteCloser, err error) {
			if err != nil || wc == nil {
				return
			}
			path := wc.URI().Path()
			wc.Close()
			outEntry.SetText(path)
		}, w)
	})

	start := widget.NewButton("START", nil)
	stop := widget.NewButton("STOP", nil)
	save := widget.NewButton("SAVE LOG", nil)
	clear := widget.NewButton("CLEAR", func() { log.clear() })

	scanner := &Scanner{}
	stop.Disable()

	parseList := func(s string) []string {
		var out []string
		for _, part := range strings.Split(s, ",") {
			if p := strings.TrimSpace(part); p != "" {
				out = append(out, p)
			}
		}
		return out
	}
	parseInt := func(s string) int {
		n, _ := strconv.Atoi(strings.TrimSpace(s))
		return n
	}

	start.OnTapped = func() {
		scanner.mu.Lock()
		if scanner.running {
			scanner.mu.Unlock()
			return
		}

		tok := strings.TrimSpace(token.Text)
		topics := parseList(topicsEntry.Text)

		if tok == "" {
			scanner.mu.Unlock()
			dialog.ShowInformation("Ошибка", "Укажи GitHub Token.", w)
			return
		}
		if len(topics) == 0 {
			scanner.mu.Unlock()
			dialog.ShowInformation("Ошибка", "Укажи хотя бы одну тему.", w)
			return
		}

		out := strings.TrimSpace(outEntry.Text)
		if out == "" {
			out = "accounts.txt"
		}

		ctx, cancel := context.WithCancel(context.Background())
		scanner.cancel = cancel
		scanner.running = true
		scanner.mu.Unlock()

		start.Disable()
		stop.Enable()

		go func() {
			wake := keepAwake("идёт сбор аккаунтов")
			defer wake()

			defer func() {
				scanner.mu.Lock()
				scanner.running = false
				scanner.cancel = nil
				scanner.mu.Unlock()

				start.Enable()
				stop.Disable()
				log.append("=== СБОР ЗАВЕРШЁН ===")
			}()

			log.append("=== Сбор аккаунтов по теме ===")
			log.append("Темы: %s", strings.Join(topics, ", "))
			if langs := parseList(langsEntry.Text); len(langs) > 0 {
				log.append("Языки: %s", strings.Join(langs, ", "))
			}

			opts := collector.Options{
				Token:       tok,
				Topics:      topics,
				Langs:       parseList(langsEntry.Text),
				OrgsOnly:    orgsCheck.Checked,
				MinStars:    parseInt(minStarsEntry.Text),
				Sort:        "stars",
				PerPage:     100,
				MaxAccounts: parseInt(maxEntry.Text),
				Sleep:       2500 * time.Millisecond,
				Progress: func(found int, msg string) {
					log.append("[%d] %s", found, msg)
				},
			}

			log.append("Запрос: %s", opts.Query())

			users, err := collector.Collect(ctx, opts)
			if err != nil && len(users) == 0 {
				log.append("[ERROR] %v", err)
				return
			}
			if err != nil {
				log.append("[WARN] %v (сохраняю частичный результат)", err)
			}

			if len(users) == 0 {
				log.append("Ничего не найдено.")
				return
			}

			before, added, after, merr := collector.MergeToFile(out, users)
			if merr != nil {
				log.append("[ERROR] %v", merr)
				return
			}

			log.append("Найдено новых: %d (было %d, всего стало %d)", added, before, after)
			log.append("Сохранено -> %s", out)
			if added == 0 && before > 0 {
				log.append("Все найденные аккаунты уже были в списке.")
			}

			outPath, _ := filepath.Abs(out)
			log.append("Передаю в «Сканер»: %s", filepath.Base(outPath))
			fyne.Do(func() {
				fileEntry.SetText(outPath)
				onCollected(outPath)
			})
		}()
	}

	stop.OnTapped = func() {
		log.append("Запрошена остановка...")
		scanner.stop()
	}

	save.OnTapped = func() {
		dialog.ShowFileSave(func(wc fyne.URIWriteCloser, err error) {
			if err != nil || wc == nil {
				return
			}
			defer wc.Close()
			_, _ = wc.Write([]byte(log.text()))
			log.append("Лог сохранён: %s", wc.URI().Path())
		}, w)
	}

	_ = w
	return container.NewBorder(
		container.NewVBox(
			widget.NewLabel("Темы (topic)"),
			topicsEntry,
			widget.NewLabel("Языки кода"),
			langsEntry,
			container.NewHBox(orgsCheck),
			container.NewGridWithColumns(2,
				container.NewVBox(widget.NewLabel("Min stars"), minStarsEntry),
				container.NewVBox(widget.NewLabel("Max аккаунтов"), maxEntry),
			),
			widget.NewLabel("Файл вывода"),
			container.NewBorder(nil, nil, nil, selectOut, outEntry),
			container.NewHBox(start, stop, save, clear),
		),
		widget.NewLabel(""),
		nil, nil,
		log.widget(),
	)
}

// ===== Вкладка 3: скан папок и архивов =====

func extractArchive(archivePath string) (string, func(), error) {
	tmp, err := os.MkdirTemp("", "gitleaks-extract-")
	if err != nil {
		return "", nil, err
	}
	cleanup := func() { _ = os.RemoveAll(tmp) }

	lower := strings.ToLower(archivePath)
	var cmd *exec.Cmd
	switch {
	case strings.HasSuffix(lower, ".zip"):
		cmd = exec.Command("unzip", "-q", "-o", archivePath, "-d", tmp)
	case strings.HasSuffix(lower, ".7z"):
		cmd = exec.Command("7z", "x", "-y", "-o"+tmp, archivePath)
	case strings.HasSuffix(lower, ".rar"):
		cmd = exec.Command("unrar", "x", "-y", archivePath, tmp+"/")
	case strings.HasSuffix(lower, ".tar"),
		strings.HasSuffix(lower, ".tar.gz"), strings.HasSuffix(lower, ".tgz"),
		strings.HasSuffix(lower, ".tar.bz2"), strings.HasSuffix(lower, ".tar.xz"):
		cmd = exec.Command("tar", "-xf", archivePath, "-C", tmp)
	default:
		cleanup()
		return "", nil, fmt.Errorf("неизвестный формат архива: %s", filepath.Base(archivePath))
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		cleanup()
		return "", nil, fmt.Errorf("распаковка: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return tmp, cleanup, nil
}

func scanDirTab(w fyne.Window) fyne.CanvasObject {
	log := newLogView()
	bindings := map[string]*widget.Label{}
	bar := statsBar(bindings)
	stats := &scanStats{} // счётчики ТОЛЬКО этой вкладки
	// Фоновые генерации отчётов (см. runAsync): одна кнопка — один запуск.
	var reportBusy, breakdownBusy atomic.Bool

	pathEntry := widget.NewEntry()
	pathEntry.SetPlaceHolder("Путь к папке или архиву (zip/tar/7z/rar)")

	selectPath := widget.NewButton("Выбрать", func() {
		dialog.ShowFolderOpen(func(lu fyne.ListableURI, err error) {
			if err != nil || lu == nil {
				return
			}
			pathEntry.SetText(lu.Path())
		}, w)
	})
	selectFile := widget.NewButton("Архив...", func() {
		dialog.ShowFileOpen(func(r fyne.URIReadCloser, err error) {
			if err != nil || r == nil {
				return
			}
			pathEntry.SetText(r.URI().Path())
			r.Close()
		}, w)
	})

	start := widget.NewButton("SCAN", nil)
	stop := widget.NewButton("STOP", nil)
	save := widget.NewButton("SAVE LOG", nil)
	clear := widget.NewButton("CLEAR", func() { log.clear() })

	report := widget.NewButton("ОТЧЁТ HTML", func() {
		runAsync(log, &reportBusy, "отчёт", func() {
			dir := pickScanDir()
			path, n, err := generateFindingsHTML(dir)
			if err != nil {
				log.append("[ERROR] отчёт: %v", err)
				return
			}
			log.append("Отчёт: %s (%d находок)", path, n)
			openBrowser(path)
		})
	})
	breakdown := widget.NewButton("РАЗБОРКА", func() {
		runAsync(log, &breakdownBusy, "разборка", func() {
			dir := pickScanDir()
			path, nr, nf, nreal, err := generateBreakdownHTML(dir)
			if err != nil {
				log.append("[ERROR] разборка: %v", err)
				return
			}
			log.append("Разборка: %d репо/целей, %d находок, похожих на боевые: %d", nr, nf, nreal)
			openBrowser(path)
		})
	})
	openLast := widget.NewButton("ПОСЛЕДНИЙ СКАН", func() {
		runAsync(log, &breakdownBusy, "разборка", func() {
			dir := pickScanDir()
			path, nr, nf, nreal, err := generateBreakdownHTML(dir)
			if err != nil {
				log.append("[ERROR] разборка: %v", err)
				return
			}
			log.append("Последний скан: %s — %d целей, %d находок, боевых: %d", dir, nr, nf, nreal)
			openBrowser(path)
		})
	})
	openDir := widget.NewButton("ОТКРЫТЬ ПАПКУ", func() {
		dir := pickScanDir()
		if err := openFolder(dir); err != nil {
			log.append("[ERROR] открыть папку: %v", err)
			return
		}
		log.append("Открываю папку: %s", dir)
	})
	clearAll := widget.NewButton("ОЧИСТИТЬ", func() { clearReports(w, log, nil) })

	sc := &Scanner{}
	stop.Disable()

	start.OnTapped = func() {
		sc.mu.Lock()
		if sc.running {
			sc.mu.Unlock()
			return
		}
		target := strings.TrimSpace(pathEntry.Text)
		if target == "" {
			sc.mu.Unlock()
			dialog.ShowInformation("Ошибка", "Укажи путь к папке или архиву.", w)
			return
		}
		gitleaksPath, gerr := findTool("gitleaks")
		if gerr != nil {
			sc.mu.Unlock()
			dialog.ShowInformation("gitleaks не найден", "Установи gitleaks.", w)
			return
		}
		if err := os.MkdirAll(reportsDir(), 0o755); err != nil {
			sc.mu.Unlock()
			dialog.ShowError(err, w)
			return
		}

		ctx, cancel := context.WithCancel(context.Background())
		sc.cancel = cancel
		sc.running = true
		sc.mu.Unlock()

		start.Disable()
		stop.Enable()

		// Счётчик ставим ДО старта горутины — окно гонки, как в scannerTab.
		activeScans.Add(1)

		go func() {
			wake := keepAwake("идёт скан папки")
			defer wake()
			defer activeScans.Add(-1)

			sd := newScanDir()

			defer func() {
				sc.mu.Lock()
				sc.running = false
				sc.cancel = nil
				sc.mu.Unlock()
				start.Enable()
				stop.Disable()
				log.append("=== СКАН ЗАВЕРШЁН ===")
			}()

			stats.reset(1)
			fyne.Do(func() { updateStats(bindings, stats) })

			scanTarget := target
			var cleanupExtract func()
			lower := strings.ToLower(target)
			isArchive := strings.HasSuffix(lower, ".zip") || strings.HasSuffix(lower, ".7z") ||
				strings.HasSuffix(lower, ".rar") || strings.HasSuffix(lower, ".tar") ||
				strings.HasSuffix(lower, ".tar.gz") || strings.HasSuffix(lower, ".tgz") ||
				strings.HasSuffix(lower, ".tar.bz2") || strings.HasSuffix(lower, ".tar.xz")

			if isArchive {
				log.append("[АРХИВ] %s — распаковываю...", filepath.Base(target))
				tmp, cl, err := extractArchive(target)
				if err != nil {
					log.append("[ERROR] %v", err)
					return
				}
				cleanupExtract = cl
				scanTarget = tmp
				log.append("Распаковано во временную папку — сканирую файлы.")
			}
			if cleanupExtract != nil {
				defer cleanupExtract()
			}

			if ctx.Err() != nil {
				return
			}

			stats.mu.Lock()
			stats.repos++
			stats.mu.Unlock()
			fyne.Do(func() { updateStats(bindings, stats) })

			reportName := "dir__" + strings.ReplaceAll(strings.TrimSuffix(filepath.Base(target), filepath.Ext(target)), "/", "_") +
				"__" + time.Now().Format("20060102_150405") + ".json"
			report := filepath.Join(sd, reportName)

			log.append("[GITLEAKS DIR] %s", scanTarget)
			var pid atomic.Int64
			pulseStop := make(chan struct{})
			pulseDone := make(chan struct{})
			go func() {
				defer close(pulseDone)
				for i := 0; i < 40 && pid.Load() == 0; i++ {
					select {
					case <-pulseStop:
						return
					case <-time.After(100 * time.Millisecond):
					}
				}
				if pid.Load() == 0 {
					return
				}
				procPulse(pulseStop, pulseDone, int(pid.Load()), scanTarget, log, 15*time.Second)
			}()

			_, code, err := runCommandStream(ctx, ".", func(line string) {
				clean := stripANSI(strings.TrimSpace(line))
				if clean != "" && (strings.Contains(clean, "scanned") || strings.Contains(clean, "leaks")) {
					log.append("    %s", clean)
				}
			}, func(p int) { pid.Store(int64(p)) },
				gitleaksPath,
				append([]string{"dir", scanTarget,
					"--report-format", "json", "--report-path", report},
					gitleaksConfigArgs()...)...,
			)
			close(pulseStop)

			if err != nil && ctx.Err() != nil {
				log.append("Остановлено пользователем.")
				return
			}
			if err != nil {
				log.append("[WARN] вывод gitleaks неполный: %v", err)
			}

			switch {
			case code == 0:
				log.append("[CLEAN] файлы чистые")
				stats.mu.Lock()
				stats.clean++
				stats.mu.Unlock()
			case code == 1:
				n := parseFindings(report)
				log.append("[FINDINGS] %d секретов -> %s", n, report)
				stats.mu.Lock()
				stats.findings++
				stats.secrets += n
				stats.mu.Unlock()
			default:
				log.append("[GITLEAKS ERROR] exit %d", code)
				stats.mu.Lock()
				stats.errors++
				stats.mu.Unlock()
			}
			fyne.Do(func() { updateStats(bindings, stats) })

			if bp, nr, nf, nreal, berr := generateBreakdownHTML(sd); berr == nil {
				log.append("Разборка: %d целей, %d находок, похожих на боевые: %d", nr, nf, nreal)
				log.append("Открыть: %s", bp)
			}
		}()
	}

	stop.OnTapped = func() {
		log.append("Запрошена остановка...")
		sc.stop()
	}

	save.OnTapped = func() {
		dialog.ShowFileSave(func(wc fyne.URIWriteCloser, err error) {
			if err != nil || wc == nil {
				return
			}
			defer wc.Close()
			_, _ = wc.Write([]byte(log.text()))
			log.append("Лог сохранён: %s", wc.URI().Path())
		}, w)
	}

	return container.NewBorder(
		container.NewVBox(
			widget.NewLabel("Папка или архив"),
			container.NewBorder(nil, nil, nil, container.NewHBox(selectPath, selectFile), pathEntry),
			container.NewHBox(start, stop, save, clear, report, breakdown, openLast, openDir, clearAll),
			widget.NewLabel("Статистика"),
			bar,
		),
		widget.NewLabel(""),
		nil, nil,
		log.widget(),
	)
}

type bigTheme struct {
	base fyne.Theme
}

func (b *bigTheme) Size(name fyne.ThemeSizeName) float32 {
	switch name {
	case theme.SizeNameText:
		return 17
	default:
		return b.base.Size(name)
	}
}

func (b *bigTheme) Color(name fyne.ThemeColorName, variant fyne.ThemeVariant) color.Color {
	return b.base.Color(name, variant)
}

func (b *bigTheme) Font(s fyne.TextStyle) fyne.Resource {
	return b.base.Font(s)
}

func (b *bigTheme) Icon(n fyne.ThemeIconName) fyne.Resource {
	return b.base.Icon(n)
}

func main() {
	const appID = "com.ihor.github-gitleaks-scanner"
	a := app.NewWithID(appID)
	a.Settings().SetTheme(&bigTheme{base: theme.DefaultTheme()})

	w := a.NewWindow("GitHub Gitleaks Scanner")
	w.Resize(fyne.NewSize(1100, 780))

	token := widget.NewPasswordEntry()
	token.SetPlaceHolder("GitHub Personal Access Token")

	const prefKeyToken = "github_token"
	token.SetText(a.Preferences().StringWithFallback(prefKeyToken, ""))
	token.OnChanged = func(s string) {
		a.Preferences().SetString(prefKeyToken, s)
	}

	fileEntry := widget.NewEntry()
	fileEntry.SetPlaceHolder("Файл с GitHub accounts")

	scanTrigger := widget.NewButton("", nil)
	scanTrigger.Hide()
	var tabs *container.AppTabs
	onCollected := func(outPath string) {
		tabs.SelectTabIndex(0)
		scanTrigger.OnTapped()
	}

	tabs = container.NewAppTabs(
		container.NewTabItem("Сканер", scannerTab(w, token, fileEntry, scanTrigger)),
		container.NewTabItem("Сбор аккаунтов", collectorTab(w, token, fileEntry, onCollected)),
		container.NewTabItem("Скан папки/архива", scanDirTab(w)),
	)

	root := container.NewBorder(
		container.NewVBox(
			widget.NewLabel("GitHub Token (общий для всех вкладок)"),
			token,
			widget.NewSeparator(),
		),
		nil, nil, nil,
		tabs,
	)

	w.SetContent(root)
	w.ShowAndRun()
}

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// Векторы пересчитаны НЕЗАВИСИМО от этого кода (Python, hashlib/hmac):
//
//	WIF  — Base58Check(0x80 || приватный ключ 0C28…AA1D);
//	xprv — BIP32 test vector 1, master-ключ из seed 000102030405060708090a0b0c0d0e0f;
//	мнемоника — стандартный вектор BIP39 (энтропия 0x00…00 → abandon … about).
const (
	testWIF      = "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ"
	testXprv     = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"
	testMnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
)

// breakChecksum меняет последний символ на валидный символ Base58:
// регулярка при этом продолжает проходить, а контрольная сумма — нет.
// Это ровно тот случай, когда verdict должен сказать «checksum не сошёлся»,
// а не «не найдено».
func breakChecksum(s string) string {
	return s[:len(s)-1] + "z"
}

func TestValidWIF(t *testing.T) {
	if !validWIF(testWIF) {
		t.Errorf("validWIF(%q) = false, ожидалось true", testWIF)
	}
	if validWIF(breakChecksum(testWIF)) {
		t.Errorf("validWIF принял WIF с подделанной контрольной суммой")
	}
	if validWIF("5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyT0") {
		t.Errorf("validWIF принял строку с невалидным символом Base58")
	}
	if !reWIF.MatchString(breakChecksum(testWIF)) {
		t.Errorf("reWIF должна пропускать формат — иначе verdict не отличит «формат?» от отсутствия формата")
	}
}

func TestValidXprv(t *testing.T) {
	if !validXprv(testXprv) {
		t.Errorf("validXprv(%q) = false, ожидалось true", testXprv)
	}
	if validXprv(breakChecksum(testXprv)) {
		t.Errorf("validXprv принял xprv с подделанной контрольной суммой")
	}
}

func TestValidateBIP39(t *testing.T) {
	cases := []struct {
		name   string
		in     string
		words  bool
		chksum bool
	}{
		{"стандартный вектор 12 слов", testMnemonic, true, true},
		{"12 abandon — контрольная сумма не сходит",
			strings.Repeat("abandon ", 11) + "abandon", true, false},
		{"неизвестное слово", "notaword abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about", false, false},
		{"неправильное число слов", "abandon abandon abandon", false, false},
		{
			"24 слова из словаря, но контрольная сумма не сходит",
			strings.Repeat("abandon ", 23) + "abandon", true, false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w, c := validateBIP39(tc.in)
			if w != tc.words || c != tc.chksum {
				t.Errorf("validateBIP39() = (%v, %v), ожидалось (%v, %v)", w, c, tc.words, tc.chksum)
			}
		})
	}
}

func TestLooksLikeSeed(t *testing.T) {
	if !looksLikeSeed(testMnemonic) {
		t.Error("looksLikeSeed отверг валидную мнемонику")
	}
	if looksLikeSeed("abandon abandon abandon") {
		t.Error("looksLikeSeed принял 3 слова")
	}
	if !looksLikeSeed("Abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about") {
		t.Error("looksLikeSeed отверг строку с заглавными буквами — кандидат должен быть регистронезависимым")
	}
	if looksLikeSeed("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon!") {
		t.Error("looksLikeSeed принял слово с не-буквенным символом")
	}
	if looksLikeSeed("abandon abandon abandon abandon abandon\nabandon abandon abandon abandon abandon abandon about") {
		t.Error("looksLikeSeed принял строку с переводом строки")
	}
}

// TestIsDevJunk — регрессия на главный баг старой версии: подстрочное
// совпадение «test» матчилось в «latest», а «doc» — в «docker», из-за чего
// настоящие секреты помечались «тест/демо» и выпадали из «боевых».
func TestIsDevJunk(t *testing.T) {
	junk := []string{
		"test/secret.go",
		"pkg/parser_test.go",
		"examples/key.env",
		"README.md",
		"docs/config.yml",
		"demo/wallet.json",
		"fixtures/seed.txt",
		".github/workflows/ci.yml",
		".travis.yml",
		"backup/key.bak",
		"docker.local/config.yml",
		"play.go",
		"testdata/mnemonic.txt",
		"vendor/github.com/stretchr/testify/README.md",
	}
	for _, p := range junk {
		if !isDevJunk(p) {
			t.Errorf("isDevJunk(%q) = false, ожидалось true", p)
		}
	}

	notJunk := []string{
		"latest/config.json",                           // "test" внутри "latest"
		"internal/contest/prize.go",                    // "test" внутри "contest"
		"pkg/attestation/verify.go",                    // "test" внутри "attestation"
		"src/docker-compose.yml",                       // "doc" внутри "docker"
		"internal/doctor/doctor.go",                    // "doc" внутри "doctor"
		"app/latest_release/wallet.json",               // релизная папка — не тесты
		"cmd/contest/main.go",                          // то же для каталога
		"vendor/github.com/stretchr/testify/assert.go", // "test" внутри "testify"
		"internal/migrations/20240101_add_wallet.sql",  // ничего тестового
	}
	for _, p := range notJunk {
		if isDevJunk(p) {
			t.Errorf("isDevJunk(%q) = true, ожидалось false (ложное срабатывание)", p)
		}
	}
}

func TestVerdict(t *testing.T) {
	cases := []struct {
		name   string
		f      gitleaksFinding
		spread int
		class  string
		status string
		combat bool
	}{
		{
			name:   "валидный WIF в боевом пути",
			f:      gitleaksFinding{Secret: testWIF, File: "internal/wallet/wif.go", Match: "wif = " + testWIF},
			class:  "WIF BTC (валид.)",
			status: "🔥 похоже на боевой",
			combat: true,
		},
		{
			name:   "валидный WIF в тестовом пути",
			f:      gitleaksFinding{Secret: testWIF, File: "test/keys_test.go", Match: "wif = " + testWIF},
			class:  "WIF BTC (валид.)",
			status: "тест/демо",
			combat: false,
		},
		{
			name:   "WIF с испорченным checksum",
			f:      gitleaksFinding{Secret: breakChecksum(testWIF), File: "wif.go", Match: "x"},
			class:  "WIF BTC (формат?)",
			status: "checksum не сошёлся",
			combat: false,
		},
		{
			name:   "валидный xprv в боевом пути",
			f:      gitleaksFinding{Secret: testXprv, File: "hd/wallet.go", Match: "xprv = " + testXprv},
			class:  "xprv HD (валид.)",
			status: "🔥 похоже на боевой",
			combat: true,
		},
		{
			name:   "валидная мнемоника в боевом пути",
			f:      gitleaksFinding{Secret: testMnemonic, File: "backend/config.go", Match: "seed: " + testMnemonic},
			class:  "seed-фраза BIP39 (валид.)",
			status: "🔥 похоже на боевой",
			combat: true,
		},
		{
			name:   "валидная мнемоника в тестовом пути",
			f:      gitleaksFinding{Secret: testMnemonic, File: "test/vectors.go", Match: "seed: " + testMnemonic},
			class:  "seed-фраза BIP39 (валид.)",
			status: "тест/демо",
			combat: false,
		},
		{
			name:   "hex64 в priv-контексте",
			f:      gitleaksFinding{Secret: strings.Repeat("ab12", 16), File: "app/config.go", Match: "private_key = " + strings.Repeat("ab12", 16)},
			class:  "hex64-ключ (priv-контекст)",
			status: "🔥 похоже на боевой",
			combat: true,
		},
		{
			name:   "hex64 без priv-контекста — это хеш",
			f:      gitleaksFinding{Secret: strings.Repeat("ab12", 16), File: "app/config.go", Match: "commit = " + strings.Repeat("ab12", 16)},
			class:  "hex64 (хеш?)",
			status: "—",
			combat: false,
		},
		{
			name:   "известный публичный ключ AWS-пример",
			f:      gitleaksFinding{Secret: "AKIAIOSFODNN7EXAMPLE", File: "README.md", Match: "AKIA"},
			status: "публичный пример",
			combat: false,
		},
		{
			name:   "GitHub PAT опознан по формату",
			f:      gitleaksFinding{Secret: "ghp_" + strings.Repeat("A", 36), File: "src/deploy.sh", Match: "TOKEN=ghp_"},
			class:  "GitHub PAT (классический)",
			status: "🔥 формат опознан",
			combat: true,
		},
		{
			name:   "JWT не боевой",
			f:      gitleaksFinding{Secret: "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abcdefghijklmnopqrstuvwxyz012345", File: "src/app.go", Match: "jwt"},
			class:  "JWT-токен",
			status: "—",
			combat: false,
		},
		{
			name:   "мусор, повторяющийся в трёх репо — шаблон",
			f:      gitleaksFinding{Secret: "someRandomSecretValue1234567890abcdefgh", File: "config/settings.py", Match: "api_key"},
			spread: 3,
			status: "шаблон (в 3 репо)",
			combat: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			class, status, combat := verdict(tc.f, tc.spread)
			if tc.class != "" && class != tc.class {
				t.Errorf("class = %q, ожидалось %q", class, tc.class)
			}
			if tc.status != "" && status != tc.status {
				t.Errorf("status = %q, ожидалось %q", status, tc.status)
			}
			if combat != tc.combat {
				t.Errorf("combat = %v, ожидалось %v", combat, tc.combat)
			}
		})
	}
}

// TestMatchSecretRuleOrder: узкие правила должны срабатывать раньше широких,
// иначе sk-ant-ключ попадёт в «OpenAI API key».
func TestMatchSecretRuleOrder(t *testing.T) {
	antKey := "sk-ant-" + strings.Repeat("a1", 20)
	r := matchSecretRule(antKey)
	if r == nil {
		t.Fatal("Anthropic-ключ не распознан")
	}
	if r.name != "Anthropic API key" {
		t.Errorf("правило = %q, ожидалось %q", r.name, "Anthropic API key")
	}

	openai := "sk-" + strings.Repeat("a1", 20)
	r = matchSecretRule(openai)
	if r == nil || r.name != "OpenAI API key" {
		t.Errorf("правило = %v, ожидалось OpenAI API key", r)
	}

	if matchSecretRule("короткий-строка") != nil {
		t.Error("правило не должно срабатывать на случайной строке")
	}
}

func TestShannonAndLooksLikeToken(t *testing.T) {
	if shannon("aaaaaaaaaaaa") != 0 {
		t.Errorf("энтропия однородной строки должна быть 0, получено %v", shannon("aaaaaaaaaaaa"))
	}
	// 26 символов, 8 повторов — энтропия ≈ 2.99 < 3.5 (пересчитано отдельно).
	if looksLikeToken("aaaabbbb111222333444555666") {
		t.Error("слабая строка с повторами принята за токен")
	}
	// 35 символов, почти все разные — энтропия ≈ 5.07.
	if !looksLikeToken("AIzaB3cD4eF5gH6jK7mN8pQ9rS1tUvWxYz0") {
		t.Error("похожий на API-ключ токен отвергнут")
	}
	// Начало «M0» — это SVG-путь, а не ключ.
	if looksLikeToken("M0123456789abcdefghijklmnop") {
		t.Error("SVG-путь принят за токен")
	}
}

// writeReport кладёт отчёт gitleaks в каталог — ровно в том формате,
// который пишет сам gitleaks (--report-format json).
func writeReport(t *testing.T, dir, name string, findings []gitleaksFinding) {
	t.Helper()
	data, err := json.Marshal(findings)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, name), data, 0o644); err != nil {
		t.Fatal(err)
	}
}

// TestWriteFileAtomicConcurrent: кнопки «РАЗБОРКА» и «ПОСЛЕДНИЙ СКАН» плюс
// авто-разборка по окончании скана могут писать один и тот же файл
// одновременно. Результат должен быть ЦЕЛИКОМ один из payload'ов:
// ни смешанных байтов, ни обрезанной записи, ни временных хвостов.
func TestWriteFileAtomicConcurrent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "_breakdown.html")

	const size = 100_000
	payloads := make([][]byte, 8)
	for i := range payloads {
		payloads[i] = bytes.Repeat([]byte{byte('A' + i)}, size)
	}

	var wg sync.WaitGroup
	for i := range payloads {
		wg.Add(1)
		go func(b []byte) {
			defer wg.Done()
			if err := writeFileAtomic(path, b); err != nil {
				t.Errorf("writeFileAtomic: %v", err)
			}
		}(payloads[i])
	}
	wg.Wait()

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != size {
		t.Fatalf("размер = %d, ожидалось %d — запись обрезана", len(got), size)
	}
	first := got[0]
	for i, c := range got {
		if c != first {
			t.Fatalf("подмешались соседние записи: байт %d = %q, ожидался %q", i, c, first)
		}
	}
	if first < 'A' || first > 'A'+7 {
		t.Fatalf("неожиданное содержимое %q", first)
	}
	assertNoTempLeftovers(t, dir, "_breakdown.html")
}

// assertNoTempLeftovers: в каталоге должны остаться только ожидаемые файлы —
// временные хвосты атомарной записи недопустимы.
func assertNoTempLeftovers(t *testing.T, dir string, want ...string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, e := range entries {
		got[e.Name()] = true
	}
	for _, w := range want {
		if !got[w] {
			t.Errorf("нет ожидаемого файла %q", w)
		}
		delete(got, w)
	}
	for name := range got {
		t.Errorf("лишний файл в каталоге: %q", name)
	}
}

func TestGenerateFindingsHTML(t *testing.T) {
	dir := t.TempDir()
	writeReport(t, dir, "alice__repo__20260101_000000.json", []gitleaksFinding{
		{
			RuleID: "generic-api-key", Description: "key",
			File: "config.go", StartLine: 12,
			Secret: "<script>alert(1)</script>",
			Match:  "token = <script>alert(1)</script>",
			Commit: "abc123",
		},
	})

	path, n, err := generateFindingsHTML(dir)
	if err != nil {
		t.Fatalf("generateFindingsHTML: %v", err)
	}
	if n != 1 {
		t.Errorf("n = %d, ожидалось 1", n)
	}
	if filepath.Base(path) != "_findings.html" {
		t.Errorf("имя отчёта = %q, ожидалось _findings.html", filepath.Base(path))
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	html := string(data)
	if strings.Contains(html, "<script>alert(1)</script>") {
		t.Error("HTML-инъекция: секрет не экранирован")
	}
	if !strings.Contains(html, "&lt;script&gt;") {
		t.Error("ожидался экранированный секрет")
	}
	if !strings.Contains(html, "abc123") {
		t.Error("ожидался хеш коммита")
	}
	assertNoTempLeftovers(t, dir, "alice__repo__20260101_000000.json", "_findings.html")
}

func TestGenerateBreakdownHTML(t *testing.T) {
	dir := t.TempDir()

	// Свежий отчёт: валидный WIF в боевом пути + публичный AWS-пример.
	writeReport(t, dir, "alice__repo__20260101_000000.json", []gitleaksFinding{
		{
			RuleID: "btc-wif", Description: "wif",
			File: "internal/wallet/wif.go", StartLine: 7,
			Secret: testWIF, Match: "wif = " + testWIF, Commit: "aaa111",
		},
		{
			RuleID: "aws-access-token", Description: "aws",
			File: "README.md", StartLine: 3,
			Secret: "AKIAIOSFODNN7EXAMPLE", Match: "AKIA", Commit: "bbb222",
		},
	})

	// Более старый отчёт той же пары аккаунт+репо: его находки брать НЕЛЬЗЯ.
	writeReport(t, dir, "alice__repo__20251231_000000.json", []gitleaksFinding{
		{
			RuleID: "stale", Description: "stale",
			File: "old.go", StartLine: 1,
			Secret: "staleSecretFromOldReport", Match: "stale", Commit: "ccc333",
		},
	})

	path, nRepos, nFindings, nReal, err := generateBreakdownHTML(dir)
	if err != nil {
		t.Fatalf("generateBreakdownHTML: %v", err)
	}
	if nRepos != 1 || nFindings != 2 || nReal != 1 {
		t.Errorf("(nRepos, nFindings, nReal) = (%d, %d, %d), ожидалось (1, 2, 1)",
			nRepos, nFindings, nReal)
	}
	if filepath.Base(path) != "_breakdown.html" {
		t.Errorf("имя отчёта = %q, ожидалось _breakdown.html", filepath.Base(path))
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	html := string(data)

	for _, want := range []string{
		"alice__repo",          // группировка по паре аккаунт+репо
		testWIF,                // боевой WIF попал в отчёт
		"🔥1 похожих на боевые", // бейдж
		"публичный пример",     // AWS-пример не считается боевым
		"WIF BTC (валид.)",     // класс
	} {
		if !strings.Contains(html, want) {
			t.Errorf("в разборке нет %q", want)
		}
	}
	if strings.Contains(html, "staleSecretFromOldReport") {
		t.Error("взяли находку из устаревшего отчёта вместо самого свежего")
	}
	assertNoTempLeftovers(t, dir,
		"alice__repo__20260101_000000.json",
		"alice__repo__20251231_000000.json",
		"_breakdown.html")
}

// TestGenerateBreakdownHTMLNoRowLimit — в отчёте не должно быть обрезки по
// числу строк: раньше репо показывало лишь первые 500 секретов, а из-под
// «... и ещё N строк» терялись десятки тысяч находок (43k в одном репо).
// Любой секрет обязан попасть в HTML, сколько бы их ни было.
func TestGenerateBreakdownHTMLNoRowLimit(t *testing.T) {
	dir := t.TempDir()

	const n = 1200 // заметно больше старого лимита 500
	fs := make([]gitleaksFinding, 0, n)
	for i := 0; i < n; i++ {
		fs = append(fs, gitleaksFinding{
			RuleID: "generic-api-key", Description: "key",
			File:   "cfg.go", StartLine: i + 1,
			Secret: fmt.Sprintf("secretNoLimit%04dXYZ", i),
			Match:  "m", Commit: "deadbee",
		})
	}
	writeReport(t, dir, "bob__big__20260101_000000.json", fs)

	path, _, nFindings, _, err := generateBreakdownHTML(dir)
	if err != nil {
		t.Fatalf("generateBreakdownHTML: %v", err)
	}
	if nFindings != n {
		t.Fatalf("nFindings = %d, ожидалось %d", nFindings, n)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	html := string(data)
	if strings.Contains(html, "и ещё") {
		t.Error("в отчёте осталась обрезка строк — лимит вернулся")
	}
	if got := strings.Count(html, "secretNoLimit"); got != n {
		t.Errorf("в HTML %d секретов, ожидалось все %d — строки обрезаны", got, n)
	}
	// Секция с находками должна быть раскрыта, иначе в браузере видно
	// лишь заголовок, а строки читаются как отсутствующие.
	if !strings.Contains(html, "<details open>") {
		t.Error("секция с находками свёрнута по умолчанию — в браузере она не видна")
	}
}

// TestHiddenSeed — валидная 12-словная фраза, спрятанная среди лишних слов
// (13/15/18/24 слова целиком), обязана находиться перебором окон.
func TestHiddenSeed(t *testing.T) {
	build := func(extraBefore, extraAfter []string) string {
		parts := append([]string{}, extraBefore...)
		parts = append(parts, strings.Split(testMnemonic, " ")...)
		parts = append(parts, extraAfter...)
		return strings.Join(parts, " ")
	}
	cases := []struct {
		name       string
		secret     string
		wantStart  int
		wantLength int
	}{
		{"12 валидных + лишнее в конце (13)", build(nil, []string{"hiddenword"}), 0, 12},
		{"лишнее в начале (13)", build([]string{"hiddenword"}, nil), 1, 12},
		{"два лишних вокруг (14)", build([]string{"noise"}, []string{"noise"}), 1, 12},
	}
	for _, tc := range cases {
		start, length, ok := hiddenSeed(tc.secret)
		if !ok {
			t.Errorf("%s: hiddenSeed не нашёл валидную фразу", tc.name)
			continue
		}
		if start != tc.wantStart || length != tc.wantLength {
			t.Errorf("%s: (start=%d len=%d), ожидалось (start=%d len=%d)",
				tc.name, start, length, tc.wantStart, tc.wantLength)
		}
	}

	// вердикт: скрытая фраза в боевом пути — боевая
	secret := build(nil, []string{"hiddenword"})
	cl, st, combat := verdict(gitleaksFinding{Secret: secret, File: "backend/config.go", Match: "seed: " + secret}, 1)
	if cl != "seed-фраза BIP39 (спрятана)" || !combat {
		t.Errorf("скрытая фраза: class=%q combat=%v, ожидалось «спрятана»/true", cl, combat)
	}
	if !strings.Contains(st, "окно 12") {
		t.Errorf("статус %q должен указывать окно 12 слов", st)
	}
	// в тестовом пути — не боевая
	_, st2, combat2 := verdict(gitleaksFinding{Secret: secret, File: "test/vectors.go", Match: "seed: " + secret}, 1)
	if combat2 || st2 != "тест/демо" {
		t.Errorf("скрытая фраза в тестовом пути: status=%q combat=%v", st2, combat2)
	}
}

// TestSeedDensity — правило «10 из 20» (и усиленное «20 из 30»): кандидат,
// но НЕ бой: на прозе порог проходит ~8% окон, поэтому checksum не заменяет.
func TestSeedDensity(t *testing.T) {
	// валидных 12 слов, но одно выбито — checksum не сойдётся
	broken := strings.Replace(testMnemonic, "abandon", "ability", 1)
	if _, _, ok := hiddenSeed(broken); ok {
		t.Fatal("hiddenSeed нашёл фразу в строке с подменённым словом — ложное срабатывание")
	}
	dict, win, strong, ok := seedDensity(broken)
	if !ok || dict < 10 || win > 20 {
		t.Errorf("seedDensity(12 словарных) = (%d,%d,%v,%v), ожидалось прохождение 10/20", dict, win, strong, ok)
	}
	if strong {
		t.Error("12/20 не должно считаться усиленным правилом 20/30")
	}

	// проза из теста gitleaks — порог 10/20 НЕ должен проходить
	prose := "The quick brown fox jumps over the lazy dog near the river bank while running fast"
	if _, _, _, ok := seedDensity(prose); ok {
		t.Error("seedDensity пропустила английскую прозу")
	}

	// вердикт: кандидат по плотности — не боевой. Строка из 13 слов
	// (не входит в 12/15/18/21/24) не проходит looksLikeSeed и не имеет
	// валидного окна — до плотности доходит именно она.
	cand := broken + " extraword"
	if _, _, ok := hiddenSeed(cand); ok {
		t.Fatal("hiddenSeed нашла окно в строке с подменённым словом")
	}
	cl, st, combat := verdict(gitleaksFinding{Secret: cand, File: "src/wallet.go", Match: "seed: " + cand}, 1)
	if combat {
		t.Errorf("кандидат по плотности помечен боевым: %q / %q", cl, st)
	}
	if cl != "seed-фраза (кандидат 10/20)" {
		t.Errorf("class = %q, ожидалось «seed-фраза (кандидат 10/20)»", cl)
	}

	// усиленное правило 20/30: 20 словарных из 24 (без валидного checksum)
	many := make([]string, 0, 24)
	for i := 0; i < 20; i++ {
		many = append(many, words24[i])
	}
	many = append(many, "notaword", "notaword2", "notaword3", "notaword4")
	dict2, _, strong2, ok2 := seedDensity(strings.Join(many, " "))
	if !ok2 || !strong2 || dict2 < 20 {
		t.Errorf("seedDensity(20 словарных из 24) = (%d, strong=%v, ok=%v), ожидалось прохождение 20/30", dict2, strong2, ok2)
	}
}

// words24 — первые 24 слова словаря: все в B39, но checksum не сходится.
var words24 = func() []string {
	w := strings.Fields(bip39List)
	return w[:24]
}()

// TestBruteForceSeed — выбитое/испорченное слово: перебором подбираем замену
// или недостающее слово. Ключевой честный момент: checksum BIP39 даёт ~128
// проходов из 2048 на позицию, поэтому функция возвращает ЧИСЛО кандидатов,
// а вердикт — всегда кандидат (не бой): подтверждение только балансом.
func TestBruteForceSeed(t *testing.T) {
	orig := strings.Fields(testMnemonic) // 12 слов: abandon×11 + about

	// 1) выбито слово: одно НЕ из словаря, длина 12
	broken := append([]string{}, orig...)
	broken[5] = "zqxjvkl" // такого слова в B39 нет
	brokenS := strings.Join(broken, " ")
	n, ok := bruteForceSeed(brokenS)
	if !ok || n == 0 {
		t.Fatalf("bruteForceSeed(выбитое слово) = (%d, %v), ожидалось >0 кандидатов", n, ok)
	}
	if n > 2048 {
		t.Errorf("кандидатов %d — больше числа слов словаря", n)
	}
	// истинная фраза обязана быть среди кандидатов: подстановка исходного
	// слова — один из 2048 вариантов и проходит checksum
	if _, csOK := validateBIP39(testMnemonic); !csOK {
		t.Fatal("эталонная фраза невалидна — тест бессмыслен")
	}

	// 2) вердикт по выбитому слову: кандидат, НЕ бой
	cl, st, combat := verdict(gitleaksFinding{Secret: brokenS, File: "src/wallet.go", Match: "mnemonic: " + brokenS}, 1)
	if cl != "seed-фраза BIP39 (перебор)" {
		t.Errorf("class = %q, ожидалось «seed-фраза BIP39 (перебор)»", cl)
	}
	if combat {
		t.Errorf("перебор помечен боевым: %q / %q (checksum не доказывает фразу)", cl, st)
	}
	if !strings.Contains(st, "кандидатов") || !strings.Contains(st, "баланс") {
		t.Errorf("статус %q должен содержать число кандидатов и слово «баланс»", st)
	}

	// 3) в тестовом пути — «тест/демо», тоже не бой
	_, st2, combat2 := verdict(gitleaksFinding{Secret: brokenS, File: "test/vectors.go", Match: "mnemonic: " + brokenS}, 1)
	if combat2 || st2 != "тест/демо" {
		t.Errorf("перебор в тестовом пути: status=%q combat=%v", st2, combat2)
	}

	// 4) пропало слово: 11 слов, все из словаря — вставка в 12 позиций
	missing := append(append([]string{}, orig[:6]...), orig[7:]...)
	missingS := strings.Join(missing, " ")
	n2, ok2 := bruteForceSeed(missingS)
	if !ok2 || n2 == 0 {
		t.Errorf("bruteForceSeed(11 слов) = (%d, %v), ожидалось >0 кандидатов", n2, ok2)
	}
	cl3, _, combat3 := verdict(gitleaksFinding{Secret: missingS, File: "src/wallet.go", Match: "seed: " + missingS}, 1)
	if cl3 != "seed-фраза BIP39 (перебор)" || combat3 {
		t.Errorf("пропавшее слово: class=%q combat=%v, ожидалось «перебор»/false", cl3, combat3)
	}

	// 5) испорчено два слова — перебор не берётся
	twice := append([]string{}, orig...)
	twice[3], twice[8] = "zqxjvkl", "mnbvcxz"
	if _, ok := bruteForceSeed(strings.Join(twice, " ")); ok {
		t.Error("bruteForceSeed согласилась на два испорченных слова")
	}

	// 6) длина вне сценария (13 слов, одно не из словаря) — не наш случай
	if _, ok := bruteForceSeed(brokenS + " extraword"); ok {
		t.Error("bruteForceSeed согласилась на 13 слов (нет валидной длины)")
	}
}

// TestGitleaksCryptoConfig — регрессия на дыру «мнемонику он не нашёл нифига»:
// в дефолтном ruleset gitleaks нет правил для BIP39/WIF/xprv, поэтому без
// встроенного gitleaks.toml сканер физически не мог увидеть кошельки.
// Интеграционно: реальный gitleaks с нашим конфигом находит все три типа
// крипто-секретов и не срабатывает на английской прозе.
func TestGitleaksCryptoConfig(t *testing.T) {
	cfgPath := gitleaksConfigPath()
	if cfgPath == "" {
		t.Fatal("gitleaksConfigPath() = \"\": не удалось разложить встроенный конфиг")
	}
	b, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatalf("чтение конфига: %v", err)
	}
	for _, want := range []string{"useDefault = true", "bip39-mnemonic", "wif-key", "bip32-xprv"} {
		if !strings.Contains(string(b), want) {
			t.Errorf("встроенный конфиг не содержит %q", want)
		}
	}
	if got := gitleaksConfigArgs(); len(got) != 2 || got[0] != "--config" || got[1] != cfgPath {
		t.Fatalf("gitleaksConfigArgs() = %v, ожидалось [--config %s]", got, cfgPath)
	}

	gitleaksBin, err := exec.LookPath("gitleaks")
	if err != nil {
		t.Skip("gitleaks не установлен — интеграционный тест пропущен")
	}

	dir := t.TempDir()
	wallet := "const cfg = {\n" +
		"  mnemonic: \"" + testMnemonic + "\",\n" +
		"  wif = \"" + testWIF + "\",\n" +
		"  xprv = \"" + testXprv + "\"\n}\n"
	if err := os.WriteFile(filepath.Join(dir, "wallet.js"), []byte(wallet), 0o600); err != nil {
		t.Fatal(err)
	}
	prose := "The quick brown fox jumps over the lazy dog near the river bank while running fast\n"
	if err := os.WriteFile(filepath.Join(dir, "prose.txt"), []byte(prose), 0o600); err != nil {
		t.Fatal(err)
	}
	// ГОЛАЯ фраза: ни слова mnemonic/seed/wallet рядом — раньше из-за
	// keywords-префильтра gitleaks её физически не видел (дыра варианта C).
	bare := testMnemonic + "\n"
	if err := os.WriteFile(filepath.Join(dir, "bare.txt"), []byte(bare), 0o600); err != nil {
		t.Fatal(err)
	}

	report := filepath.Join(dir, "report.json")
	args := append([]string{"dir", dir}, gitleaksConfigArgs()...)
	args = append(args, "--report-format", "json", "--report-path", report)
	_ = exec.Command(gitleaksBin, args...).Run() // exit 1 при находках — ожидаемо

	b, err = os.ReadFile(report)
	if err != nil {
		t.Fatalf("отчёт gitleaks не создан: %v", err)
	}
	var findings []gitleaksFinding
	if err := json.Unmarshal(b, &findings); err != nil {
		t.Fatalf("разбор отчёта: %v", err)
	}

	byRule := map[string]bool{}
	for _, f := range findings {
		byRule[f.RuleID] = true
	}
	for _, rule := range []string{"bip39-mnemonic", "wif-key", "bip32-xprv"} {
		if !byRule[rule] {
			t.Errorf("правило %q не сработало; найдено %d находок", rule, len(findings))
		}
	}
	for _, f := range findings {
		if strings.HasSuffix(f.File, "prose.txt") {
			t.Errorf("ложное срабатывание на прозе: %s (%s)", f.RuleID, f.Secret)
		}
	}
	bareFound := false
	for _, f := range findings {
		if f.RuleID == "bip39-mnemonic" && strings.HasSuffix(f.File, "bare.txt") {
			bareFound = true
		}
	}
	if !bareFound {
		t.Error("голая сид-фраза (bare.txt, без слов mnemonic/seed/wallet) не найдена — дыра keywords вернулась")
	}
}

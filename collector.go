// Package collector ищет GitHub-аккаунты по темам через Search API.
// Используется и CLI (cmd/topic2accounts), и GUI (вкладка «Сбор аккаунтов»).
package collector

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// User — один найденный аккаунт (владелец репозитория).
type User struct {
	Login   string `json:"login"`
	Type    string `json:"type"` // User | Organization
	HTMLURL string `json:"html_url"`
}

// repo — результат /search/repositories: нужен только владелец.
type repo struct {
	FullName string `json:"full_name"`
	Stars    int    `json:"stargazers_count"`
	Owner    User   `json:"owner"`
}

type searchResponse struct {
	TotalCount        int    `json:"total_count"`
	IncompleteResults bool   `json:"incomplete_results"`
	Items             []repo `json:"items"`
}

// Options — параметры сбора.
//
// ВАЖНО: квалификатор topic: работает только в /search/repositories,
// поэтому сбор идёт по репозиториям, а аккаунтами считаются их владельцы.
type Options struct {
	Token       string
	Topics      []string // например: crypto, solidity
	Langs       []string // например: go, rust
	OrgsOnly    bool     // оставлять только организации
	MinStars    int      // минимум звёзд у репозитория
	Sort        string   // stars | forks | updated (или "")
	PerPage     int      // 1..100
	MaxAccounts int      // 0 = без лимита
	Sleep       time.Duration

	// Progress вызывается из горутины сбора: (найдено всего, статусная строка).
	Progress func(found int, msg string)
}

// ValidSort проверяет значение sort.
func ValidSort(s string) bool {
	switch s {
	case "", "stars", "forks", "updated":
		return true
	}
	return false
}

// Query строит строку запроса Search API (по репозиториям).
func (o *Options) Query() string {
	parts := make([]string, 0, len(o.Topics)+len(o.Langs)+2)
	for _, t := range o.Topics {
		parts = append(parts, "topic:"+t)
	}
	for _, l := range o.Langs {
		parts = append(parts, "language:"+l)
	}
	if o.MinStars > 0 {
		parts = append(parts, "stars:>="+strconv.Itoa(o.MinStars))
	}
	// Пробел, не «+»: url.Values.Encode() сам превратит его в корректный разделитель.
	return strings.Join(parts, " ")
}

// Collect ищет репозитории по темам и возвращает уникальных владельцев,
// отсортированных по логину. Останавливается по ctx (частичный результат).
func Collect(ctx context.Context, o Options) ([]User, error) {
	if len(o.Topics) == 0 {
		return nil, fmt.Errorf("укажи хотя бы одну тему (topic)")
	}
	if strings.TrimSpace(o.Token) == "" {
		return nil, fmt.Errorf("не задан GitHub токен")
	}
	if !ValidSort(o.Sort) {
		return nil, fmt.Errorf("неверная сортировка: %q", o.Sort)
	}

	perPage := o.PerPage
	if perPage < 1 || perPage > 100 {
		perPage = 100
	}
	sleep := o.Sleep
	if sleep <= 0 {
		sleep = 2500 * time.Millisecond
	}

	client := &http.Client{Timeout: 30 * time.Second}
	accounts := map[string]User{}

	progress := o.Progress
	if progress == nil {
		progress = func(int, string) {}
	}

	total := 0
	warned := false

	for page := 1; ; page++ {
		if ctx.Err() != nil {
			break
		}

		q := url.Values{}
		q.Set("q", o.Query())
		q.Set("per_page", strconv.Itoa(perPage))
		q.Set("page", strconv.Itoa(page))
		if o.Sort != "" {
			q.Set("sort", o.Sort)
			q.Set("order", "desc")
		}

		resp, err := search(ctx, client, o.Token, q)
		if err != nil {
			if len(accounts) > 0 {
				break // вернём частичный результат
			}
			return nil, err
		}

		if page == 1 {
			total = resp.TotalCount
			progress(len(accounts), fmt.Sprintf("репозиториев по теме: %d", total))
			if total > 1000 && !warned {
				progress(len(accounts), "warning: Search API отдаёт максимум 1000 репозиториев — дроби тему (языки, stars)")
				warned = true
			}
			if resp.IncompleteResults {
				progress(len(accounts), "warning: incomplete_results=true, результаты могут быть неполными")
			}
		}

		newOwners := 0
		for _, r := range resp.Items {
			if o.OrgsOnly && r.Owner.Type != "Organization" {
				continue
			}
			if _, ok := accounts[r.Owner.Login]; !ok {
				accounts[r.Owner.Login] = r.Owner
				newOwners++
			}
		}
		progress(len(accounts), fmt.Sprintf("страница %d: репозиториев +%d, новых аккаунтов +%d", page, len(resp.Items), newOwners))

		if len(resp.Items) < perPage {
			break
		}
		if o.MaxAccounts > 0 && len(accounts) >= o.MaxAccounts {
			break
		}

		select {
		case <-ctx.Done():
			// Остановка запрошена — выходим с тем, что уже собрали.
		case <-time.After(sleep):
			continue
		}
		break
	}

	logins := make([]string, 0, len(accounts))
	for login := range accounts {
		logins = append(logins, login)
	}
	sort.Strings(logins)

	users := make([]User, 0, len(logins))
	for _, l := range logins {
		users = append(users, accounts[l])
	}

	progress(len(users), fmt.Sprintf("собрано %d аккаунтов", len(users)))
	return users, ctx.Err()
}

// ReadLogins читает файл аккаунтов: по одному логину на строку.
// Пустые строки и комментарии (#) пропускаются, как в accounts.txt у сканера.
// Несуществующий файл — это не ошибка: возвращается пустой список.
func ReadLogins(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()

	var logins []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		u := strings.TrimSpace(sc.Text())
		if u != "" && !strings.HasPrefix(u, "#") {
			logins = append(logins, u)
		}
	}
	return logins, sc.Err()
}

// WriteLogins перезаписывает файл указанным списком логинов.
//
// Запись атомарная (временный файл в том же каталоге + rename): падение
// посреди записи больше не обнуляет accounts.txt, а читатель никогда не
// увидит наполовину записанный список.
func WriteLogins(path string, logins []string) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp")
	if err != nil {
		return err
	}
	name := tmp.Name()

	fail := func(err error) error {
		_ = tmp.Close()
		_ = os.Remove(name)
		return err
	}

	bw := bufio.NewWriter(tmp)
	for _, l := range logins {
		if _, werr := fmt.Fprintln(bw, l); werr != nil {
			return fail(werr)
		}
	}
	if err := bw.Flush(); err != nil {
		return fail(err)
	}
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

// MergeToFile добавляет новых пользователей в файл, не затирая старые записи.
// Возвращает: логинов было, добавлено, всего стало, ошибка.
func MergeToFile(path string, users []User) (before, added, after int, err error) {
	existing := map[string]bool{}

	old, err := ReadLogins(path)
	if err != nil {
		return 0, 0, 0, err
	}
	for _, l := range old {
		existing[l] = true
	}
	before = len(existing)

	for _, u := range users {
		if !existing[u.Login] {
			existing[u.Login] = true
			added++
		}
	}
	after = len(existing)

	// Пишем объединённый список заново: он остаётся отсортированным и без дублей.
	all := make([]string, 0, after)
	for l := range existing {
		all = append(all, l)
	}
	sort.Strings(all)

	return before, added, after, WriteLogins(path, all)
}

func search(ctx context.Context, client *http.Client, token string, q url.Values) (*searchResponse, error) {
	const maxAttempts = 5

	for attempt := 1; ; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet,
			"https://api.github.com/search/repositories?"+q.Encode(), nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Accept", "application/vnd.github+json")
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

		resp, err := client.Do(req)
		if err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			return nil, err
		}

		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		switch {
		case resp.StatusCode == http.StatusOK:
			var out searchResponse
			if err := json.Unmarshal(body, &out); err != nil {
				return nil, err
			}
			return &out, nil

		case resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusTooManyRequests:
			wait := time.Duration(attempt*15) * time.Second
			if reset := resp.Header.Get("X-RateLimit-Reset"); reset != "" {
				if ts, err := strconv.ParseInt(reset, 10, 64); err == nil {
					if d := time.Until(time.Unix(ts, 0)); d > wait && d < time.Hour {
						wait = d + time.Second
					}
				}
			}
			if attempt >= maxAttempts {
				return nil, fmt.Errorf("HTTP %d после %d попыток: %s",
					resp.StatusCode, attempt, strings.TrimSpace(string(body)))
			}
			// Ожидание прерывается по ctx: кнопка STOP сработает сразу,
			// а не через оставшиеся секунды/минуты.
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(wait):
			}

		default:
			return nil, fmt.Errorf("GitHub API: HTTP %d: %s",
				resp.StatusCode, strings.TrimSpace(string(body)))
		}
	}
}

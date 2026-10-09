// topic2accounts — собирает список GitHub-аккаунтов (юзеров и/или оргов)
// по тематике (topic) через GitHub Search API и пишет логины построчно
// (готово для accounts.txt у github-scanner).
//
// Примеры:
//
//	export GITHUB_TOKEN=ghp_xxx
//	topic2accounts -topic crypto -min-repos 3 -min-followers 5
//	topic2accounts -topic solidity -topic ethereum -lang go -out accounts.txt
//	topic2accounts -topic machine-learning -orgs
package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github-scanner/internal/collector"
)

type multiFlag []string

func (m *multiFlag) String() string { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error {
	for _, part := range strings.Split(v, ",") {
		if p := strings.TrimSpace(part); p != "" {
			*m = append(*m, p)
		}
	}
	return nil
}

func main() {
	var (
		topics  multiFlag
		langs   multiFlag
		orgs    bool
		minStar int
		sort    string
		out     string
		token   string
		perPage int
		maxAcc  int
		sleep   time.Duration
	)
	flag.Var(&topics, "topic", "Тематика (можно несколько, поиск по всем сразу: AND)")
	flag.Var(&langs, "lang", "Язык кода, например go (можно несколько)")
	flag.BoolVar(&orgs, "orgs", false, "Оставлять только организации")
	flag.IntVar(&minStar, "min-stars", 0, "Минимум звёзд у репозитория")
	flag.StringVar(&sort, "sort", "stars", "Сортировка: stars | forks | updated")
	flag.StringVar(&out, "out", "-", "Файл вывода (- = stdout)")
	flag.StringVar(&token, "token", "", "GitHub PAT (иначе GITHUB_TOKEN / GH_TOKEN)")
	flag.IntVar(&perPage, "per-page", 100, "Результатов на страницу (макс 100)")
	flag.IntVar(&maxAcc, "max", 0, "Остановиться после N аккаунтов (0 = без лимита)")
	flag.DurationVar(&sleep, "sleep", 2500*time.Millisecond, "Пауза между запросами (лимит Search API 30/мин)")
	// По умолчанию дописываем с дедупликацией; -append=false перезаписывает файл.
	appendMode := true
	flag.BoolVar(&appendMode, "append", true, "Дописывать в файл с дедупликацией (false = перезаписать)")

	flag.Parse()

	if len(topics) == 0 {
		fmt.Fprintln(os.Stderr, "error: укажи хотя бы один -topic")
		flag.Usage()
		os.Exit(2)
	}

	token = strings.TrimSpace(token)
	if token == "" {
		token = strings.TrimSpace(os.Getenv("GITHUB_TOKEN"))
	}
	if token == "" {
		token = strings.TrimSpace(os.Getenv("GH_TOKEN"))
	}
	if token == "" {
		fmt.Fprintln(os.Stderr, "error: не задан токен: используй -token или export GITHUB_TOKEN=...")
		os.Exit(2)
	}

	opts := collector.Options{
		Token:       token,
		Topics:      topics,
		Langs:       langs,
		OrgsOnly:    orgs,
		MinStars:    minStar,
		Sort:        sort,
		PerPage:     perPage,
		MaxAccounts: maxAcc,
		Sleep:       sleep,
		Progress: func(found int, msg string) {
			fmt.Fprintf(os.Stderr, "[%d] %s\n", found, msg)
		},
	}

	users, err := collector.Collect(context.Background(), opts)
	if err != nil {
		// Частичная выборка при остановке — всё равно сохраняем.
		if len(users) == 0 {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "warning: %v (сохраняю частичный результат)\n", err)
	}

	if out != "-" && appendMode {
		before, added, after, merr := collector.MergeToFile(out, users)
		if merr != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", merr)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "новых: %d (было %d, всего стало %d) -> %s\n", added, before, after, out)
		return
	}

	w := os.Stdout
	closeW := func() {}
	if out != "-" {
		f, ferr := os.Create(out)
		if ferr != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", ferr)
			os.Exit(1)
		}
		w = f
		closeW = func() { f.Close() }
	}
	defer closeW()

	bw := bufio.NewWriter(w)
	defer bw.Flush()

	// Пишем только логины — accounts.txt у github-scanner читает по одному юзеру на строку.
	for _, u := range users {
		fmt.Fprintln(bw, u.Login)
	}
}

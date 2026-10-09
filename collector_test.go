package collector

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestValidSort(t *testing.T) {
	for _, s := range []string{"", "stars", "forks", "updated"} {
		if !ValidSort(s) {
			t.Errorf("ValidSort(%q) = false, ожидалось true", s)
		}
	}
	for _, s := range []string{"Stars", "commits", "recent", "star"} {
		if ValidSort(s) {
			t.Errorf("ValidSort(%q) = true, ожидалось false", s)
		}
	}
}

func TestOptionsQuery(t *testing.T) {
	cases := []struct {
		name string
		o    Options
		want string
	}{
		{
			name: "темы + языки + минимум звёзд",
			o:    Options{Topics: []string{"crypto", "solidity"}, Langs: []string{"go"}, MinStars: 10},
			want: "topic:crypto topic:solidity language:go stars:>=10",
		},
		{
			name: "только темы",
			o:    Options{Topics: []string{"ethereum"}},
			want: "topic:ethereum",
		},
		{
			name: "min stars = 0 не добавляет квалификатор",
			o:    Options{Topics: []string{"crypto"}, MinStars: 0},
			want: "topic:crypto",
		},
		{
			name: "пустые опции",
			o:    Options{},
			want: "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Разделитель — пробел: url.Values.Encode() сам экранирует его в "+".
			if got := tc.o.Query(); got != tc.want {
				t.Errorf("Query() = %q, ожидалось %q", got, tc.want)
			}
		})
	}
}

func TestReadLogins(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "accounts.txt")
	content := "# комментарий\n\nalice\n  bob  \n\n# ещё один\ncarol\n"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	got, err := ReadLogins(path)
	if err != nil {
		t.Fatalf("ReadLogins: %v", err)
	}
	want := []string{"alice", "bob", "carol"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("ReadLogins = %v, ожидалось %v", got, want)
	}

	// Несуществующий файл — не ошибка (так задокументировано).
	none, err := ReadLogins(filepath.Join(dir, "missing.txt"))
	if err != nil || none != nil {
		t.Errorf("ReadLogins(несуществующий) = (%v, %v), ожидалось (nil, nil)", none, err)
	}
}

// TestWriteLoginsAtomic: проверяем и round-trip, и то, что временный файл
// не остаётся в каталоге — иначе сливки от предыдущей записи накапливаются.
func TestWriteLoginsAtomic(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "accounts.txt")

	if err := WriteLogins(path, []string{"zeta", "alpha"}); err != nil {
		t.Fatalf("WriteLogins: %v", err)
	}

	got, err := ReadLogins(path)
	if err != nil {
		t.Fatalf("ReadLogins: %v", err)
	}
	if want := []string{"zeta", "alpha"}; !reflect.DeepEqual(got, want) {
		t.Errorf("ReadLogins = %v, ожидалось %v", got, want)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "accounts.txt" {
		var names []string
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Errorf("в каталоге остались временные файлы: %v", names)
	}
}

func TestWriteLoginsBadDir(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "no-such-dir", "accounts.txt")
	if err := WriteLogins(missing, []string{"alice"}); err == nil {
		t.Error("WriteLogins в несуществующий каталог должен возвращать ошибку")
	}
	if _, err := os.Stat(missing); err == nil {
		t.Error("файл не должен появиться при ошибке")
	}
}

func TestMergeToFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "accounts.txt")
	if err := WriteLogins(path, []string{"zeta", "alpha"}); err != nil {
		t.Fatal(err)
	}

	users := []User{
		{Login: "beta"},
		{Login: "alpha"}, // уже есть
		{Login: "gamma"},
	}
	before, added, after, err := MergeToFile(path, users)
	if err != nil {
		t.Fatalf("MergeToFile: %v", err)
	}
	if before != 2 || added != 2 || after != 4 {
		t.Errorf("MergeToFile = (%d, %d, %d), ожидалось (2, 2, 4)", before, added, after)
	}

	got, err := ReadLogins(path)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"alpha", "beta", "gamma", "zeta"} // отсортировано и без дублей
	if !reflect.DeepEqual(got, want) {
		t.Errorf("файл после слияния = %v, ожидалось %v", got, want)
	}
}

// TestMergeToFileCreatesFile: слияние в ещё несуществующий файл не ошибка.
func TestMergeToFileCreatesFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "new.txt")
	before, added, after, err := MergeToFile(path, []User{{Login: "solo"}})
	if err != nil {
		t.Fatalf("MergeToFile: %v", err)
	}
	if before != 0 || added != 1 || after != 1 {
		t.Errorf("MergeToFile = (%d, %d, %d), ожидалось (0, 1, 1)", before, added, after)
	}
	got, err := ReadLogins(path)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"solo"}; !reflect.DeepEqual(got, want) {
		t.Errorf("файл = %v, ожидалось %v", got, want)
	}
}

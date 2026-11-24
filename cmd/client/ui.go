package main

import (
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"safevault/internal/access"
)

// Affichage dans le terminal : couleurs seulement vers un terminal, et jamais si NO_COLOR
// est défini (https://no-color.org).
var useColor = func() bool {
	if os.Getenv("NO_COLOR") != "" || os.Getenv("TERM") == "dumb" {
		return false
	}
	info, err := os.Stdout.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}()

func paint(code, s string) string {
	if !useColor {
		return s
	}
	return "\033[" + code + "m" + s + "\033[0m"
}

func bold(s string) string  { return paint("1", s) }
func dim(s string) string   { return paint("2", s) }
func green(s string) string { return paint("32", s) }
func red(s string) string   { return paint("31", s) }
func yellow(s string) string {
	return paint("33", s)
}

// success, warn et info écrivent une ligne de résultat.
func success(format string, args ...any) {
	fmt.Println(green("✓") + " " + fmt.Sprintf(format, args...))
}
func warn(format string, args ...any) { fmt.Println(yellow("!") + " " + fmt.Sprintf(format, args...)) }
func info(format string, args ...any) { fmt.Println(dim(fmt.Sprintf(format, args...))) }

// table écrit des colonnes alignées ; la première ligne est l'en-tête.
type table struct {
	w *tabwriter.Writer
}

func newTable(header ...string) *table {
	t := &table{w: tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)}
	for i, h := range header {
		header[i] = bold(h)
	}
	fmt.Fprintln(t.w, strings.Join(header, "\t"))
	return t
}

func (t *table) row(cells ...string) { fmt.Fprintln(t.w, strings.Join(cells, "\t")) }
func (t *table) flush()              { t.w.Flush() }

// humanSize écrit une taille en octets lisible.
func humanSize(n uint64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d o", n)
	}
	div, exp := uint64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return strings.Replace(fmt.Sprintf("%.1f %cio", float64(n)/float64(div), "KMGTPE"[exp]), ".", ",", 1)
}

// humanDate écrit une date Unix ; 0 donne « - ».
func humanDate(unix int64) string {
	if unix == 0 {
		return "-"
	}
	return time.Unix(unix, 0).Format("02/01/2006 15:04")
}

// humanExpiry écrit la fin d'un accès ; 0 donne « jamais ».
func humanExpiry(unix int64) string {
	if unix == 0 {
		return "jamais"
	}
	return time.Unix(unix, 0).Format("02/01/2006 15:04")
}

// rights écrit des droits « rwsdm » suivis de leur sens en clair.
func rightsLabel(r uint32) string {
	if r == access.All {
		return access.RightsString(r) + " (tous)"
	}
	return access.RightsString(r)
}

// shortID raccourcit un identifiant de fichier pour l'affichage ; les commandes acceptent
// ce début d'identifiant.
func shortID(id string) string {
	if len(id) > 8 {
		return id[:8]
	}
	return id
}

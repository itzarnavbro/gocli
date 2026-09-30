package cli

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/term"
)

type IO interface {
	ReadCommand(prompt string) (string, error)
	ReadLine(prompt string) (string, error)
	ReadPassword(prompt string) (string, error)
	io.Writer
}

type completable interface {
	SetCompleter(fn func(prefix string) []string)
}

func NewIO() IO {
	if term.IsTerminal(int(os.Stdin.Fd())) && term.IsTerminal(int(os.Stdout.Fd())) {
		return newTTY()
	}
	fmt.Fprintln(os.Stderr, "warning: stdin is not a terminal; passwords will be echoed")
	return NewPlain(os.Stdin, os.Stdout)
}

// raw terminal input ke liye temporary raw mode use hota hai, taaki normal output disturb na ho.
type ttyIO struct {
	fd, outFd int
	cmd, ans  *term.Terminal
	complete  func(prefix string) []string
}

func newTTY() *ttyIO {
	rw := struct {
		io.Reader
		io.Writer
	}{os.Stdin, os.Stdout}

	t := &ttyIO{
		fd:    int(os.Stdin.Fd()),
		outFd: int(os.Stdout.Fd()),
		cmd:   term.NewTerminal(rw, ""),
		ans:   term.NewTerminal(rw, ""),
	}
	t.cmd.AutoCompleteCallback = t.onKey
	return t
}

func (t *ttyIO) Write(p []byte) (int, error)           { return os.Stdout.Write(p) }
func (t *ttyIO) SetCompleter(fn func(string) []string) { t.complete = fn }

func (t *ttyIO) ReadCommand(prompt string) (string, error) {
	return t.read(t.cmd, prompt, false)
}
func (t *ttyIO) ReadLine(prompt string) (string, error) {
	return t.read(t.ans, prompt, false)
}
func (t *ttyIO) ReadPassword(prompt string) (string, error) {
	return t.read(t.ans, prompt, true)
}

func (t *ttyIO) read(tm *term.Terminal, prompt string, secret bool) (string, error) {
	old, err := term.MakeRaw(t.fd)
	if err != nil {
		return "", err
	}
	defer func() { _ = term.Restore(t.fd, old) }()

	if w, h, err := term.GetSize(t.outFd); err == nil {
		_ = tm.SetSize(w, h)
	}
	if secret {
		return tm.ReadPassword(prompt)
	}
	tm.SetPrompt(prompt)
	return tm.ReadLine()
}

func (t *ttyIO) onKey(line string, pos int, key rune) (string, int, bool) {
	if key != '\t' || t.complete == nil {
		return "", 0, false
	}
	if pos > len(line) {
		pos = len(line)
	}
	head, tail := line[:pos], line[pos:]
	if strings.ContainsAny(head, " \t") {
		return "", 0, false
	}
	matches := t.complete(head)
	if len(matches) == 0 {
		return "", 0, false
	}
	c := commonPrefix(matches)
	if len(matches) == 1 {
		c += " "
	}
	if c == head {
		return "", 0, false
	}
	return c + tail, len(c), true
}

func commonPrefix(ss []string) string {
	if len(ss) == 0 {
		return ""
	}
	p := ss[0]
	for _, s := range ss[1:] {
		for !strings.HasPrefix(s, p) {
			p = p[:len(p)-1]
		}
	}
	return p
}

type plainIO struct {
	r *bufio.Reader
	w io.Writer
}

func NewPlain(r io.Reader, w io.Writer) IO { return &plainIO{bufio.NewReader(r), w} }

func (p *plainIO) Write(b []byte) (int, error)                { return p.w.Write(b) }
func (p *plainIO) ReadCommand(prompt string) (string, error)  { return p.ReadLine(prompt) }
func (p *plainIO) ReadPassword(prompt string) (string, error) { return p.ReadLine(prompt) }

func (p *plainIO) ReadLine(prompt string) (string, error) {
	_, _ = fmt.Fprint(p.w, prompt)
	line, err := p.r.ReadString('\n')
	if err != nil && (!errors.Is(err, io.EOF) || line == "") {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}

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

// IO is everything the shell needs from the outside world.
type IO interface {
	ReadCommand(prompt string) (string, error)  // main prompt: history + tab-completion
	ReadLine(prompt string) (string, error)     // answer to a question
	ReadPassword(prompt string) (string, error) // masked when on a real terminal
	io.Writer
}

// completable is implemented by IOs that can tab-complete command names.
type completable interface {
	SetCompleter(fn func(prefix string) []string)
}

// NewIO returns a raw-terminal IO when stdin/stdout are terminals,
// and a plain line-based IO otherwise (pipes, CI).
func NewIO() IO {
	if term.IsTerminal(int(os.Stdin.Fd())) && term.IsTerminal(int(os.Stdout.Fd())) {
		return newTTY()
	}
	fmt.Fprintln(os.Stderr, "warning: stdin is not a terminal; passwords will be echoed")
	return NewPlain(os.Stdin, os.Stdout)
}

// ---- real terminal ----

// ttyIO uses two Terminals so command history (up/down) holds only commands,
// not usernames. The terminal is in raw mode only while reading, so normal
// output and log lines behave as usual in between.
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

// onKey completes the command word when Tab is pressed.
func (t *ttyIO) onKey(line string, pos int, key rune) (string, int, bool) {
	if key != '\t' || t.complete == nil {
		return "", 0, false
	}
	if pos > len(line) {
		pos = len(line)
	}
	head, tail := line[:pos], line[pos:]
	if strings.ContainsAny(head, " \t") { // only the first word is completed
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

// ---- plain IO (pipes and tests) ----

type plainIO struct {
	r *bufio.Reader
	w io.Writer
}

func NewPlain(r io.Reader, w io.Writer) IO { return &plainIO{bufio.NewReader(r), w} }

func (p *plainIO) Write(b []byte) (int, error)                { return p.w.Write(b) }
func (p *plainIO) ReadCommand(prompt string) (string, error)  { return p.ReadLine(prompt) }
func (p *plainIO) ReadPassword(prompt string) (string, error) { return p.ReadLine(prompt) } // echoed

func (p *plainIO) ReadLine(prompt string) (string, error) {
	_, _ = fmt.Fprint(p.w, prompt)
	line, err := p.r.ReadString('\n')
	if err != nil && (!errors.Is(err, io.EOF) || line == "") { // keep a final unterminated line
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}

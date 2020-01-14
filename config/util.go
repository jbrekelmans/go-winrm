package config

import (
	"bufio"
	"fmt"
	"io"

	"unicode"
	"unicode/utf8"

	log "github.com/sirupsen/logrus"
)

type winrmConfig struct{}

var encodingError interface{} = &struct{}{}

type winrmConfigParser struct {
	line     []byte
	linePos  int
	rune     rune
	runeSize int
	ret      map[string]interface{}
	scanner  *bufio.Scanner
}

func newWinrmConfigParser(r io.Reader) *winrmConfigParser {
	scanner := bufio.NewScanner(r)
	p := &winrmConfigParser{
		ret:     map[string]interface{}{},
		scanner: scanner,
	}
	return p
}

// isEndOfLine returns whether the entire line has been consumed
func (p *winrmConfigParser) isEndOfLine() bool {
	return p.linePos == len(p.line)
}

// parseLine is a wrapper around parseLineCore that converts panics of encoding errors into a return value.
// One could say we abuse panics to simplify parsing code.
func (p *winrmConfigParser) parseLine() (err error) {
	// returning is a flag used to to distinguish between no panic and panic(nil)
	returning := false
	defer func() {
		if returning {
			return
		}
		panicVal := recover()
		if panicVal == encodingError {
			if err == nil {
				err = fmt.Errorf("incorectly encoded utf8 sequence")
			}
			return
		}
		panic(panicVal)
	}()
	err = p.parseLineCore()
	returning = true
	return
}

func (p *winrmConfigParser) parseLineCore() error {
	p.setLinePos(0)
	indentChars := 0
	for !p.isEndOfLine() {
		if !unicode.IsSpace(p.rune) {
			break
		}
		indentChars++
		p.advanceWithinLine()
	}
	if p.isEndOfLine() {
		return nil
	}
	if p.rune == '=' {
		return fmt.Errorf("the first non-space character on a line must not be =")
	}
	tokenStart := p.linePos
	// TODO check indent error here...
	for {
		p.advanceWithinLine()
		if p.isEndOfLine() {
			key := string(p.line[tokenStart:p.linePos])
			log.Debugf("parsed key %#v (object start)", key)
			return nil
		}
		if p.rune == '=' || unicode.IsSpace(p.rune) {
			break
		}
	}
	key := string(p.line[tokenStart:p.linePos])
	for {
		p.advanceWithinLine()
		if p.isEndOfLine() {
			return fmt.Errorf("line has only white space after equal sign, but expected a value")
		}
		if !unicode.IsSpace(p.rune) {
			break
		}
	}
	tokenStart = p.linePos
	for {
		p.advanceWithinLine()
		if p.isEndOfLine() {
			break
		}
	}
	value := string(p.line[tokenStart:p.linePos])

	// TODO parse value from any non-white space sequence
	log.Debugf("parsed key value pair %#v = %#v", key, value)

	return fmt.Errorf("not implemented")
}

func (p *winrmConfigParser) advanceWithinLine() {
	p.setLinePos(p.linePos + p.runeSize)
}

func (p *winrmConfigParser) setLinePos(linePos int) {
	p.linePos = linePos
	if p.linePos < len(p.line) {
		p.rune, p.runeSize = utf8.DecodeRune(p.line[p.linePos:])
		if p.rune == utf8.RuneError {
			panic(encodingError)
		}
	}
}

func (p *winrmConfigParser) Run() (*winrmConfig, error) {
	for {
		isEOF := false
		if !p.scanner.Scan() {
			if err := p.scanner.Err(); err != nil {
				return nil, err
			}
			isEOF = true
		}
		p.line = p.scanner.Bytes()
		err := p.parseLine()
		if err != nil {
			return nil, err
		}
		if isEOF {
			break
		}
	}
	return nil, fmt.Errorf("not implemented: constructing return value")
}

// Parse parses output structured like winrm get winrm/config
func Parse(r io.Reader) (interface{}, error) {
	return newWinrmConfigParser(r).Run()
}

package main

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
	defer func() {
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
		p.lineAdvance()
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
		p.lineAdvance()
		if p.isEndOfLine() {
			token := p.line[tokenStart:p.linePos]
			// TODO this is a key-value pair of type object
			log.Print(token)
			return nil
		}
	}
	// 3. check indent (error if indent per level does not match, create indent)
	// 4. read sequence of any char except space, tab, \n and =
	// 5. skip longest white space sequence (space and tab)
	// 6. if = then skip and
	//		6a. skip longest white space sequence
	//		6b. read sequence of any char except space, tab and \n
	//      6c. parse property value into bool (true or false), int (^[0-9]+$) or string (other)
	//      6d. if property is already set on parent object...
	// 7. else
	//	    7a. if next character is not \n then abort with error
	// 		7b. value is an empty object (map[string]interface{})
}

func (p *winrmConfigParser) lineAdvance() {
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

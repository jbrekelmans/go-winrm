package soap

import (
	"bytes"
	"encoding/base64"
	"encoding/xml"
	"io"
	"strconv"
	"strings"

	"github.com/gofrs/uuid"
)

// Locale is a constant for the locale that is hardcoded in SOAP headers created by this package.
const Locale = "en-US"

// MimeType is the mime type of SOAP content.
const MimeType = "application/soap+xml"

func prefix(sb *strings.Builder, to string, maxEnvelopeSize int, operationTimeoutSec int, messageID uuid.UUID, action, shellID string) {
	sb.WriteString(`<?xml version="1.0" encoding="utf-8"?>` +
		`<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:r="http://schemas.microsoft.com/wbem/wsman/1/windows/shell" xmlns:w="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd" xmlns:p="http://schemas.microsoft.com/wbem/wsman/1/wsman.xsd">` +
		`<s:Header>` +
		`<a:To>`)
	_ = xml.EscapeText(sb, []byte(to))
	sb.WriteString(`</a:To>`)
	sb.WriteString(`<a:ReplyTo>` +
		`<a:Address mustUnderstand="true">http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:Address>` +
		`</a:ReplyTo>` +
		`<w:MaxEnvelopeSize mustUnderstand="true">`)
	sb.WriteString(strconv.FormatInt(int64(maxEnvelopeSize), 10))
	sb.WriteString(`</w:MaxEnvelopeSize>` +
		`s<w:OperationTimeout>PT`)
	sb.WriteString(strconv.FormatInt(int64(operationTimeoutSec), 10))
	sb.WriteString(`S</w:OperationTimeout>
		<a:MessageID>uuid:`)
	sb.WriteString(messageID.String())
	sb.WriteString(`</a:MessageID>` +
		`<w:Locale mustUnderstand="false" xml:lang="en-US"/>` +
		`<p:DataLocale mustUnderstand="false" xml:lang="en-US"/>` +
		`<a:Action mustUnderstand="true">`)
	sb.WriteString(action)
	sb.WriteString(`</a:Action>` +
		`<w:ResourceURI mustUnderstand="true">http://schemas.microsoft.com/wbem/wsman/1/windows/shell/cmd</w:ResourceURI><w:SelectorSet>` +
		`<w:Selector Name="ShellId">`)
	_ = xml.EscapeText(sb, []byte(shellID))
	sb.WriteString(`</w:Selector>` +
		`</w:SelectorSet>`)
}

func StartCommandRequest(
	to string,
	maxEnvelopeSize int,
	operationTimeoutSec int,
	messageID uuid.UUID,
	shellID string,
	winrsConsoleModeStdin bool,
	winrsSkipCmdShell bool,
	command string,
	args []string,
) string {
	var sb strings.Builder
	prefix(
		&sb, to, maxEnvelopeSize, operationTimeoutSec, messageID,
		"http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Command",
		shellID,
	)
	if winrsConsoleModeStdin || winrsSkipCmdShell {
		sb.WriteString(`<w:OptionSet>`)
		if winrsConsoleModeStdin {
			sb.WriteString(`<w:Option Name="WINRS_CONSOLEMODE_STDIN">TRUE</w:Option>`)
		}
		if winrsSkipCmdShell {
			sb.WriteString(`<w:Option Name="WINRS_SKIP_CMD_SHELL">TRUE</w:Option>`)
		}
		sb.WriteString(`</w:OptionSet>`)
	}
	sb.WriteString(`</s:Header>` +
		`<s:Body>` +
		`<r:CommandLine>` +
		`<r:Command>`)
	_ = emitCData(&sb, []byte(command))
	sb.WriteString(`</r:Command>`)
	for _, arg := range args {
		sb.WriteString(`<r:Arguments>`)
		_ = emitCData(&sb, []byte(arg))
		sb.WriteString(`</r:Arguments>`)
	}
	sb.WriteString(`</r:CommandLine>` +
		`</s:Body>` +
		`</s:Envelope>`)
	return sb.String()
}

func SendInputRequest(
	to string,
	maxEnvelopeSize int,
	operationTimeoutSec int,
	messageID uuid.UUID,
	shellID,
	commandID string,
	data []byte,
	end bool) string {
	var sb strings.Builder
	prefix(&sb, to, maxEnvelopeSize, operationTimeoutSec, messageID, "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Send", shellID)
	sb.WriteString(`</s:Header>` +
		`<s:Body>` +
		`<r:Send>` +
		`<r:Stream Name="stdin" CommandId="`)
	sb.WriteString(commandID)
	sb.WriteString(`" End="`)
	if end {
		sb.WriteString("true")
	} else {
		sb.WriteString("false")
	}
	sb.WriteString(`">`)
	n := base64.StdEncoding.EncodedLen(len(data))
	sb.Grow(n)
	sb.WriteString(base64.StdEncoding.EncodeToString(data))
	sb.WriteString(`</r:Stream>` +
		`</r:Send>` +
		`</s:Body>` +
		`</s:Envelope>`)
	return sb.String()
}

var cdataStart = []byte("<![CDATA[")
var cdataEscape = []byte("]]]]><![CDATA[>")
var cdataEnd = []byte("]]>")

func emitCData(w io.Writer, b []byte) error {
	_, err := w.Write(cdataStart)
	if err != nil {
		return err
	}
	for {
		i := bytes.Index(b, cdataEnd)
		if i < 0 {
			_, err = w.Write(b)
			if err != nil {
				return err
			}
			break
		}
		_, err = w.Write(b[:i])
		if err != nil {
			return err
		}
		_, err = w.Write(cdataEscape)
		if err != nil {
			return err
		}
		b = b[i+len(cdataEnd):]
	}
	_, err = w.Write(cdataEnd)
	return err
}

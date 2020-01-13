package soap

import (
	"encoding/base64"
	"encoding/xml"
	"strconv"
	"strings"

	"github.com/gofrs/uuid"
)

const Locale = "en-US"
const cdataStart = "<![CDATA["
const cdataEnd = "]]>"
const MimeType = "application/soap+xml"

var deleteShellRequestXML = `<?xml version="1.0" encoding="utf-8" ?>
<env:Envelope xmlns:env="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:rsp="http://schemas.microsoft.com/wbem/wsman/1/windows/shell" xmlns:w="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd" xmlns:p="http://schemas.microsoft.com/wbem/wsman/1/wsman.xsd">
    <env:Header>
        <a:To>https://:0/wsman</a:To>
        <a:ReplyTo>
            <a:Address mustUnderstand="true">http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:Address>
        </a:ReplyTo>
        <w:MaxEnvelopeSize mustUnderstand="true">153600</w:MaxEnvelopeSize>
        <w:OperationTimeout>PT60S</w:OperationTimeout>
        <a:MessageID>uuid:01fc5687-efd7-497d-81bd-4c926328c685</a:MessageID>
        <w:Locale mustUnderstand="false" xml:lang="en-US"/>
        <p:DataLocale mustUnderstand="false" xml:lang="en-US"/>
        <a:Action mustUnderstand="true">http://schemas.xmlsoap.org/ws/2004/09/transfer/Delete</a:Action>
        <w:SelectorSet>
            <w:Selector Name="ShellId">7F21D4E2-1D38-47EB-AE43-D9317176A71B</w:Selector>
        </w:SelectorSet>
        <w:ResourceURI mustUnderstand="true">http://schemas.microsoft.com/wbem/wsman/1/windows/shell/cmd</w:ResourceURI>
    </env:Header>
    <env:Body/>
</env:Envelope>`

var deleteShellResponseXML = `<s:Envelope xml:lang="en-US" xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:w="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd" xmlns:p="http://schemas.microsoft.com/wbem/wsman/1/wsman.xsd">
	<s:Header>
		<a:Action>http://schemas.xmlsoap.org/ws/2004/09/transfer/DeleteResponse</a:Action>
		<a:MessageID>uuid:0C989AC4-DB3B-4173-B10D-E65FDDF4BB67</a:MessageID>
		<a:To>http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:To>
		<a:RelatesTo>uuid:938a6170-9710-45da-bec9-3853c2aae62f</a:RelatesTo>
	</s:Header>
	<s:Body></s:Body>
</s:Envelope>`

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
		`<r:Command>` +
		cdataStart)
	if strings.Contains(command, cdataEnd) {
		panic("args contains an invalid arg")
	}
	sb.WriteString(command)
	sb.WriteString(cdataEnd + `</r:Command>`)
	for _, arg := range args {
		if strings.Contains(arg, cdataEnd) {
			panic("args contains an invalid arg")
		}
		sb.WriteString(`<r:Arguments>` + cdataStart)
		sb.WriteString(arg)
		sb.WriteString(cdataEnd + `</r:Arguments>`)
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

var sendInputResponseXMLs = `<s:Envelope xml:lang="en-US" xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:x="http://schemas.xmlsoap.org/ws/2004/09/transfer" xmlns:w="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd" xmlns:rsp="http://schemas.microsoft.com/wbem/wsman/1/windows/shell" xmlns:p="http://schemas.microsoft.com/wbem/wsman/1/wsman.xsd"><s:Header><a:Action>http://schemas.microsoft.com/wbem/wsman/1/windows/shell/SendResponse</a:Action><a:MessageID>uuid:2A92D724-5FFE-49E3-9ED6-F68438E0571A</a:MessageID><a:To>http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:To><a:RelatesTo>uuid:46e256c3-1689-4f29-be93-5032f2cb3b66</a:RelatesTo></s:Header><s:Body><rsp:SendResponse/></s:Body></s:Envelope>`

var createCommandResponseXML = `<s:Envelope xml:lang="en-US" xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:x="http://schemas.xmlsoap.org/ws/2004/09/transfer" xmlns:w="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd" xmlns:rsp="http://schemas.microsoft.com/wbem/wsman/1/windows/shell" xmlns:p="http://schemas.microsoft.com/wbem/wsman/1/wsman.xsd"><s:Header><a:Action>http://schemas.microsoft.com/wbem/wsman/1/windows/shell/CommandResponse</a:Action><a:MessageID>uuid:5B004CAF-A1E2-41AE-B908-799A548A1877</a:MessageID><a:To>http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:To><a:RelatesTo>uuid:af857101-d599-4f82-b058-a4d882b00ca6</a:RelatesTo></s:Header><s:Body><rsp:CommandResponse><rsp:CommandId>EA821749-FEEF-43E4-88F8-17862C84AB49</rsp:CommandId></rsp:CommandResponse></s:Body></s:Envelope>`

var signalRequestXML = `<?xml version="1.0" encoding="utf-8" ?>
<env:Envelope xmlns:env="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:rsp="http://schemas.microsoft.com/wbem/wsman/1/windows/shell" xmlns:w="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd" xmlns:p="http://schemas.microsoft.com/wbem/wsman/1/wsman.xsd">
	<env:Header>
		<a:To>https://35.201.4.189:5986/wsman</a:To>
		<a:ReplyTo>
			<a:Address mustUnderstand="true">http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:Address>
		</a:ReplyTo>
		<w:MaxEnvelopeSize mustUnderstand="true">153600</w:MaxEnvelopeSize>
		<w:OperationTimeout>PT60S</w:OperationTimeout>
		<a:MessageID>uuid:b000670a-c317-488f-a348-1ed941479e91</a:MessageID>
		<w:Locale mustUnderstand="false" xml:lang="en-US"/>
		<p:DataLocale mustUnderstand="false" xml:lang="en-US"/>
		<a:Action mustUnderstand="true">http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Signal</a:Action>
		<w:SelectorSet>
			<w:Selector Name="ShellId">1E91CCDE-F96D-4592-B3E8-5E24B607777F</w:Selector>
		</w:SelectorSet>
		<w:ResourceURI mustUnderstand="true">http://schemas.microsoft.com/wbem/wsman/1/windows/shell/cmd</w:ResourceURI>
	</env:Header>
	<env:Body>
		<rsp:Signal CommandId="EA821749-FEEF-43E4-88F8-17862C84AB49">
			<rsp:Code>http://schemas.microsoft.com/wbem/wsman/1/windows/shell/signal/terminate</rsp:Code>
		</rsp:Signal>
	</env:Body>
</env:Envelope>`

var signalResponseXML = `<s:Envelope xml:lang="en-US" xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:x="http://schemas.xmlsoap.org/ws/2004/09/transfer" xmlns:w="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd" xmlns:rsp="http://schemas.microsoft.com/wbem/wsman/1/windows/shell" xmlns:p="http://schemas.microsoft.com/wbem/wsman/1/wsman.xsd">
	<s:Header>
		<a:Action>http://schemas.microsoft.com/wbem/wsman/1/windows/shell/SignalResponse</a:Action>
		<a:MessageID>uuid:B96305BD-8E7C-4252-99F1-C941451233BA</a:MessageID>
		<a:To>http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:To>
		<a:RelatesTo>uuid:b000670a-c317-488f-a348-1ed941479e91</a:RelatesTo>
	</s:Header>
	<s:Body>
		<rsp:SignalResponse/>
	</s:Body>
</s:Envelope>`

var getOutputRequestXML = `<?xml version="1.0" encoding="utf-8" ?>
<env:Envelope xmlns:env="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:rsp="http://schemas.microsoft.com/wbem/wsman/1/windows/shell" xmlns:w="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd" xmlns:p="http://schemas.microsoft.com/wbem/wsman/1/wsman.xsd">
	<env:Header>
		<a:To>https://:0/wsman</a:To>
		<a:ReplyTo>
			<a:Address mustUnderstand="true">http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:Address>
		</a:ReplyTo>
		<w:MaxEnvelopeSize mustUnderstand="true">153600</w:MaxEnvelopeSize>
		<w:OperationTimeout>PT60S</w:OperationTimeout>
		<a:MessageID>uuid:faf5622f-7de1-45ea-8f5c-2322bcdc52cc</a:MessageID>
		<w:Locale mustUnderstand="false" xml:lang="en-US"/>
		<p:DataLocale mustUnderstand="false" xml:lang="en-US"/>
		<a:Action mustUnderstand="true">http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Receive</a:Action>
		<w:SelectorSet>
			<w:Selector Name="ShellId">466EB194-6521-4CA7-B8CD-437DAF1ED707</w:Selector>
		</w:SelectorSet>
		<w:ResourceURI mustUnderstand="true">http://schemas.microsoft.com/wbem/wsman/1/windows/shell/cmd</w:ResourceURI>
	</env:Header>
	<env:Body>
		<rsp:Receive>
			<rsp:DesiredStream CommandId="B811A252-E237-4C03-9BBA-39DBE62572CA">stdout stderr</rsp:DesiredStream>
		</rsp:Receive>
	</env:Body>
</env:Envelope>`

var getOutputResponseXML = `<s:Envelope xml:lang="en-US" xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:w="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd" xmlns:rsp="http://schemas.microsoft.com/wbem/wsman/1/windows/shell" xmlns:p="http://schemas.microsoft.com/wbem/wsman/1/wsman.xsd">
	<s:Header>
		<a:Action>http://schemas.microsoft.com/wbem/wsman/1/windows/shell/ReceiveResponse</a:Action>
		<a:MessageID>uuid:C71F7791-FCCA-480B-8B66-A3E040780EC7</a:MessageID>
		<a:To>http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:To>
		<a:RelatesTo>uuid:b27928b5-8a5b-41ab-95bc-0e3b7f4bc8a1</a:RelatesTo>
	</s:Header>
	<s:Body>
		<rsp:ReceiveResponse>
			<rsp:Stream Name="stdout" CommandId="A3E7B241-AD1F-4823-8329-F8260977DD81">IFZvbHVtZSBpbiBkcml2ZSBDIGhhcyBubyBsYWJlbC4NCg==</rsp:Stream>
			<rsp:Stream Name="stdout" CommandId="A3E7B241-AD1F-4823-8329-F8260977DD81">IFZvbHVtZSBTZXJpYWwgTnVtYmVyIGlzIEY2OEItNDJFRg0KDQogRGlyZWN0b3J5IG9mIEM6XHdvcmtzcGFjZTJcc2NyaXB0c1xjbG91ZC1idWlsZGVycy1jb21tdW5pdHlcd2luZG93cy1idWlsZGVyDQoNCjAxLzEzLzIwMjAgIDA2OjM1IEFNICAgIDxESVI+ICAgICAgICAgIC4NCjAxLzEzLzIwMjAgIDA2OjM1IEFNICAgIDxESVI+ICAgICAgICAgIC4uDQowMS8xMy8yMDIwICAwNjozNSBBTSAgICAgICAgICAgICA2LDExMSBSRUFETUUubWQNCjAxLzEzLzIwMjAgIDA2OjM1IEFNICAgIDxESVI+ICAgICAgICAgIHNjcmlwdHMNCiAgICAgICAgICAgICAgIDEgRmlsZShzKSAgICAgICAgICA2LDExMSBieXRlcw0KICAgICAgICAgICAgICAgMyBEaXIocykgIDE4LDA2Nyw4NzMsNzkyIGJ5dGVzIGZyZWUNCg==</rsp:Stream>
			<rsp:Stream Name="stdout" CommandId="A3E7B241-AD1F-4823-8329-F8260977DD81" End="true"></rsp:Stream>
			<rsp:Stream Name="stderr" CommandId="A3E7B241-AD1F-4823-8329-F8260977DD81" End="true"></rsp:Stream>
			<rsp:CommandState CommandId="A3E7B241-AD1F-4823-8329-F8260977DD81" State="http://schemas.microsoft.com/wbem/wsman/1/windows/shell/CommandState/Done">
				<rsp:ExitCode>0</rsp:ExitCode>
			</rsp:CommandState>
		</rsp:ReceiveResponse>
	</s:Body>
</s:Envelope>`

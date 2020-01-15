package winrm

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"io/ioutil"
	"mime"
	"net/http"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"unsafe"

	"github.com/gofrs/uuid"
	soap "github.com/jbrekelmans/winrm/soap"
	zenwinrm "github.com/masterzen/winrm"
	zensoap "github.com/masterzen/winrm/soap"
	log "github.com/sirupsen/logrus"
)

// MaxCommandLineSize is the maximum size of a command with zero additional arguments, in bytes.
// The value is 8157, even though Microsoft documents a maximum command line size of 8191.
// The difference is the result of emperical testing (i.e. (*Client).StartCommand failing commands larger than 8157).
const MaxCommandLineSize = 8157
const zeroUUID = "00000000-0000-0000-0000-000000000000"

// LogFieldShellID is the name of the field containing the WinRM Shell identifier.
const LogFieldShellID = "shell_id"

// LogFieldCommandID is the name of the field containing the WinRM Command identifier.
const LogFieldCommandID = "cmd_id"

// See init to learn why this exists.
var dummyEndpoint = zenwinrm.NewEndpoint("", 0, true, false, nil, nil, nil, 0)

// Client contains:
// 1. a HTTP client and context for HTTP requests made with that client.
// 2. default parameters for SOAP headers.
// 3. Credentials used to authenticate with WinRM.
type Client struct {
	ctx                            context.Context
	httpClient                     *http.Client
	password                       string
	zenClient                      *zenwinrm.Client
	url                            string
	user                           string
	defaultOperationTimeoutSeconds int
	sendInputMax                   int
	zenParams                      *zenwinrm.Parameters
}

// NewClient returns a *Client and guards against some erroneous inputs.
// To use basic authentication, set password to a non-empty string.
// If password is the empty string, then client will not pass a basic authentiction header to HTTP requests,
// but other authentication mechanisms can still be implemented in the supplied HTTP client.
func NewClient(
	// ctx is not respected by shells associated with this client, or commands associated with such shells, but only by HTTP requests.
	ctx context.Context,
	useTLS bool,
	host string,
	port int,
	user, password string,
	httpClient *http.Client,
	maxEnvelopeSize *int) (*Client, error) {
	c := &Client{
		ctx:                            ctx,
		httpClient:                     httpClient,
		password:                       password,
		url:                            FormatURL(useTLS, host, port),
		user:                           user,
		defaultOperationTimeoutSeconds: 60,
	}
	if c.ctx == nil {
		return nil, fmt.Errorf("ctx must not be nil")
	}
	// Choose an arbitrary probably-large-enough minimum to have at least some validation.
	if maxEnvelopeSize != nil && *maxEnvelopeSize < 5000 {
		return nil, fmt.Errorf("maxEnvelopeSize must be at least 5000")
	}
	if c.httpClient == nil {
		c.httpClient = http.DefaultClient
	}
	err := c.init(maxEnvelopeSize)
	if err != nil {
		return nil, err
	}
	c.sendInputMax = c.computeSendInputMax()
	return c, nil
}

// See init to learn why this adapter exists.
type zenTransporterAdapter struct {
	client *Client
}

func (t *zenTransporterAdapter) Transport(endpoint *zenwinrm.Endpoint) error {
	return nil
}

func (t *zenTransporterAdapter) Post(zenClient *zenwinrm.Client, request *zensoap.SoapMessage) (string, error) {
	return t.client.doPost(request.String())
}

func (c *Client) init(maxEnvelopeSize *int) error {
	var err error
	// We now initialize zenClient with a custom transport, reasoning is as follows:
	// 1. winrm unnecessarily creates a http.Client instance for each request: https://github.com/masterzen/winrm/blob/1d17eaf15943ca3554cdebb3b1b10aaa543a0b7e/http.go#L82
	// 2. winrm does not close the response body in the error case: https://github.com/masterzen/winrm/blob/1d17eaf15943ca3554cdebb3b1b10aaa543a0b7e/http.go#L95
	// 3. winrm's check for the response content type is fishy: https://github.com/masterzen/winrm/blob/1d17eaf15943ca3554cdebb3b1b10aaa543a0b7e/http.go#L21
	//    See doPost for a more solid approach.
	c.zenParams = new(zenwinrm.Parameters)
	*c.zenParams = *zenwinrm.DefaultParameters
	if c.zenParams.Locale != soap.Locale {
		panic("zenParams default locale changed, please update this script")
	}
	if maxEnvelopeSize != nil {
		c.zenParams.EnvelopeSize = *maxEnvelopeSize
	}
	c.zenParams.Timeout = fmt.Sprintf("PT%dS", c.defaultOperationTimeoutSeconds)
	t := &zenTransporterAdapter{
		client: c,
	}
	c.zenParams.TransportDecorator = func() zenwinrm.Transporter {
		return t
	}
	c.zenClient, err = zenwinrm.NewClientWithParameters(
		dummyEndpoint, // values are computed based on this argument, or copied from this argument by winrm, but these are invisible side
		// effects that have no effect on the behavior, if you study the code.
		"", // username is purposely set to the empty string since doPost handles authentication
		"", // password is purposely set to the empty string since doPost handles authentication
		c.zenParams,
	)
	return err
}

// doPostErrorResponse is an implementation of the error interface that can be used to optionally parse SOAP payloads in HTTP responses with
// non-2xx status.
type doPostErrorResponse struct {
	Method       string
	URL          string
	StatusCode   int
	ResponseBody string
	s            string
}

func (d *doPostErrorResponse) Error() string {
	if d.s == "" {
		d.s = fmt.Sprintf("server responded to %s %#v with unexpected HTTP status %d, body prefix: %#v", d.Method, d.URL, d.StatusCode, d.ResponseBody)
	}
	return d.s
}

func (c *Client) doPost(requestBody string) (string, error) {
	method := http.MethodPost
	req, err := http.NewRequestWithContext(c.ctx, method, c.url, strings.NewReader(requestBody))
	if err != nil {
		return "", fmt.Errorf("error creating request %s %#v: %w", method, c.url, err)
	}
	req.Header.Set("Content-Type", soap.MimeType+";charset=UTF-8")
	if c.password != "" {
		req.SetBasicAuth(c.user, c.password)
	}
	res, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("error doing HTTP request %s %#v: %w", method, c.url, err)
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		var errorInfo strings.Builder
		_, err = io.Copy(&errorInfo, res.Body)
		if err != nil && err != io.EOF {
			log.WithFields(log.Fields{
				"method":     method,
				"url":        c.url,
				log.ErrorKey: err.Error(),
			}).Errorf("error while reading response body of HTTP request")
		}
		return "", &doPostErrorResponse{
			Method:       method,
			URL:          c.url,
			StatusCode:   res.StatusCode,
			ResponseBody: errorInfo.String(),
		}
	}
	contentTypeStrings := res.Header["Content-Type"]
	if len(contentTypeStrings) != 1 {
		return "", fmt.Errorf("server responded to %s %#v with HTTP status %d but the response has %d Content-Type headers", method, c.url, res.StatusCode, len(contentTypeStrings))
	}
	mimeType, _, err := mime.ParseMediaType(contentTypeStrings[0])
	if mimeType != soap.MimeType {
		return "", fmt.Errorf("server responded to %s %#v with HTTP status %d but the Content-Type has unexpected mime type %#v", method, c.url, res.StatusCode, mimeType)
	}
	resBodyData, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return "", fmt.Errorf("error while reading response body of HTTP request %s %#v: %w", method, c.url, err)
	}
	log.Tracef("request/response:\n%s\n%s", requestBody, resBodyData)
	// zenwinrm requires a string so we convert from []byte.
	// go defines strings to contain UTF-8 encoded text, but this is not necessarily the case here.
	// This is not a problem however, since zenwinrm reinterpets the string as bytes later on: https://github.com/masterzen/winrm/blob/1d17eaf15943ca3554cdebb3b1b10aaa543a0b7e/shell.go#L19
	return string(resBodyData), nil
}

func getID(data interface{}) string {
	reflectDataPtr := reflect.ValueOf(data)
	reflectData := reflect.Indirect(reflectDataPtr)
	idMember := reflectData.FieldByName("id")
	ptrToIDUnsafe := unsafe.Pointer(idMember.UnsafeAddr())
	ptrToID := (*string)(ptrToIDUnsafe)
	id := *ptrToID
	return id
}

// CreateShell creates a cmd.exe Shell that can be used to run commands.
func (c *Client) CreateShell() (*Shell, error) {
	zenShell, err := c.zenClient.CreateShell()
	if err != nil {
		return nil, err
	}
	id := getID(zenShell)
	log.WithFields(log.Fields{
		LogFieldShellID: id,
	}).Debugf("created remote winrm shell")
	return &Shell{
		c:        c,
		id:       id,
		zenShell: zenShell,
	}, nil
}

// SendInputMax returns the maximum value number of bytes that can be sent in one
// request, given the current settings of c.
func (c *Client) SendInputMax() int {
	return c.sendInputMax
}

func (c *Client) computeSendInputMax() int {
	maxEnvelopeSize := c.ZenParametersConst().EnvelopeSize
	requestBody := soap.SendInputRequest(c.URL(), maxEnvelopeSize, c.defaultOperationTimeoutSeconds, uuid.UUID{}, zeroUUID, zeroUUID, nil,
		false)
	sendInputMaxBase64 := maxEnvelopeSize - len(requestBody)
	return sendInputMaxBase64 / 4 * 3
}

// URL returns the WinRM URL associated with this client.
func (c *Client) URL() string {
	return c.url
}

// ZenParametersConst returns the *"github.com/masterzen/winrm".Parameters associated with this client.
// The value pointed to should not be modified. This function is usefull when creating requests manually to compute
// size bounds (e.g. "github.com/masterzen/winrm".NewExecuteCommandRequest).
func (c *Client) ZenParametersConst() *zenwinrm.Parameters {
	return c.zenParams
}

// Shell represents a WinRM remote shell. See (*Client).CreateShell.
type Shell struct {
	c        *Client
	zenShell *zenwinrm.Shell
	id       string
}

// Client returns the *Client associated with this shell. All commands created from this Shell perform HTTP requests
// using this client.
func (s *Shell) Client() *Client {
	return s.c
}

// Close deletes the remote shell.
func (s *Shell) Close() error {
	err := s.zenShell.Close()
	if err == nil {
		log.WithFields(log.Fields{
			LogFieldShellID: s.id,
		}).Debugf("deleted remote winrm shell")
	}
	return err
}

// ID returns the ID of this Shell
func (s *Shell) ID() string {
	return s.id
}

type commandReader struct {
	buffer  []byte
	err     error
	isEOF   bool
	hasData *sync.Cond
	mutex   sync.Mutex
}

func newCommandReader() *commandReader {
	c := &commandReader{}
	c.hasData = sync.NewCond(&c.mutex)
	// We use a finalizer to ensure we can log errors instead of silently ignoring them, in some edge cases.
	runtime.SetFinalizer(c, (*commandReader).onFinalize)
	return c
}

func (c *commandReader) onFinalize() {
	if c.err != nil {
		err := c.err
		c.err = nil
		log.WithFields(log.Fields{
			log.ErrorKey: err.Error(),
		}).Errorf("reporting otherwise hidden error in finalizer of *commandReader")
	}
}

// Read writes up to len(p) bytes from the remote command's output stream (stdout or stderr) to p.
// n is the number of bytes read. See io.Reader for more information on the contract.
func (c *commandReader) Read(p []byte) (n int, err error) {
	if len(p) == 0 {
		return 0, nil
	}
	c.mutex.Lock()
	defer c.mutex.Unlock()
	for {
		n = copy(p, c.buffer)
		c.buffer = c.buffer[n:]
		if c.isEOF {
			if c.err != nil {
				err = c.err
				c.err = nil
			} else {
				err = io.EOF
			}
			return
		}
		if n > 0 {
			return
		}
		c.hasData.Wait()
	}
}

func (c *commandReader) Write(p []byte) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	if c.isEOF {
		panic("(*commandReader).Write after close")
	}
	if len(p) == 0 {
		return
	}
	c.buffer = append(c.buffer, p...)
	c.hasData.Signal()
}

func (c *commandReader) Close(err error) bool {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	if c.isEOF {
		return false
	}
	c.err = err
	c.isEOF = true
	c.hasData.Broadcast()
	return true
}

type commandWriter struct {
	c *Command
}

// StartCommand starts a command on the remote shell.
// winrsConsoleModeStdin and winrsSkipCmdShell correspond to the SOAP options WINRS_CONSOLEMODE_STDIN and WINRS_SKIP_CMD_SHELL, respectively,
// and are defined here: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-wsmv/c793e333-c409-43c6-a2eb-6ae2489c7ef4
func (s *Shell) StartCommand(command string, args []string, winrsConsoleModeStdin, winrsSkipCmdShell bool) (*Command, error) {
	messageID, err := uuid.NewV4()
	if err != nil {
		return nil, err
	}
	client := s.Client()
	zenParams := client.ZenParametersConst()
	requestBody := soap.StartCommandRequest(
		client.URL(),
		zenParams.EnvelopeSize,
		client.defaultOperationTimeoutSeconds,
		messageID,
		s.id,
		winrsConsoleModeStdin,
		winrsSkipCmdShell,
		command,
		args,
	)
	responseBody, err := client.doPost(requestBody)
	if err != nil {
		return nil, err
	}
	commandID, err := zenwinrm.ParseExecuteCommandResponse(responseBody)
	if err != nil {
		return nil, err
	}
	log.WithFields(log.Fields{
		LogFieldCommandID: commandID,
	}).Debugf("started")
	cmd := &Command{
		exitCode: -1,
		id:       commandID,
		shell:    s,
	}
	cmd.stdout = newCommandReader()
	cmd.Stdout = cmd.stdout
	cmd.stderr = newCommandReader()
	cmd.Stderr = cmd.stderr
	return cmd, nil
}

// Command represents a command running in a remote cmd.exe terminal, and should not be used directly. See (*Shell).StartCommand.
type Command struct {
	errorCount int64
	err        error
	exitCode   int64
	id         string
	shell      *Shell
	stdout     *commandReader
	stderr     *commandReader
	stdin      *commandWriter
	// Stdout is an io.Reader representing the remote command's stdout.
	Stdout io.Reader
	// Stderr is an io.Reader representing the remote command's stderr.
	Stderr io.Reader
}

// SendInput copies bytes to the remote command's stdin. Set end to true to close the command process' stdin.
// len(p) must be at most c.Shell().Client().SendInputMax(). It is up to caller to ensure len(p) is not too
// large.
func (c *Command) SendInput(p []byte, end bool) error {
	client := c.shell.Client()
	if len(p) > client.SendInputMax() {
		return fmt.Errorf("p is too large")
	}
	messageID, err := uuid.NewV4()
	if err != nil {
		return fmt.Errorf("error generating uuid: %w", err)
	}
	requestBody := soap.SendInputRequest(
		client.URL(), client.ZenParametersConst().EnvelopeSize,
		client.defaultOperationTimeoutSeconds, messageID,
		c.shell.ID(), c.id, p,
		end)

	log.WithFields(log.Fields{
		LogFieldCommandID: c.id,
		"end":             end,
	}).Debugf("sending %d bytes of input", len(p))
	_, err = client.doPost(requestBody)
	if err != nil {
		return fmt.Errorf("error sending input to command %s: %w", c.id, err)
	}
	return nil
}

// ExitCode returns the exit code of the remote command, or -1 if it has not yet terminated.
// Use Wait to wait for the remote command to terminate.
func (c *Command) ExitCode() int {
	return int(atomic.LoadInt64(&c.exitCode))
}

// ID returns the WinRM identifier of this command.
func (c *Command) ID() string {
	return c.id
}

// Signal sends a termination signal to the remote command.
func (c *Command) Signal() {
	client := c.shell.Client()
	requestBody := zenwinrm.NewSignalRequest(client.URL(), c.shell.ID(), c.ID(), client.ZenParametersConst())
	log.WithFields(log.Fields{
		LogFieldCommandID: c.id,
	}).Debugf("sending signal")
	client.doPost(requestBody.String())
}

// Shell returns the Shell from which this command was started.
func (c *Command) Shell() *Shell {
	return c.shell
}

func (c *Command) closeStdoutAndStderr(err error, logError bool) {
	c.stdout.Close(err)
	if !c.stderr.Close(err) && logError && err != nil {
		log.WithFields(log.Fields{
			LogFieldCommandID: c.id,
			log.ErrorKey:      err.Error(),
		}).Debugf("error while getting output of command")
	}
}

func (c *Command) completed(exitCode int, err error, logError bool) {
	atomic.StoreInt64(&c.exitCode, int64(exitCode))
	c.closeStdoutAndStderr(err, logError)
	log.WithFields(log.Fields{
		LogFieldCommandID: c.id,
	}).Debugf("completed with exit code %d and %d error(s)", exitCode, atomic.LoadInt64(&c.errorCount))
}

func (c *Command) getOutputLoop() {
	for {
		client := c.shell.Client()
		requestBody := zenwinrm.NewGetOutputRequest(client.URL(), c.shell.ID(), c.ID(), "stdout stderr", client.ZenParametersConst())
		requestBodyString := requestBody.String()
		log.WithFields(log.Fields{
			LogFieldCommandID: c.id,
		}).Debugf("getting output")
		responseBody, err := client.doPost(requestBodyString)
		if err != nil {
			if strings.Contains(err.Error(), "OperationTimeout") {
				// Operation timeout because there was no command output
				continue
			}
			atomic.AddInt64(&c.errorCount, 1)
			c.completed(16001, fmt.Errorf("error getting output of command %s: %w", c.id, err), true)
			break
		}
		var stdout bytes.Buffer
		var stderr bytes.Buffer
		ended, exitCode, err := zenwinrm.ParseSlurpOutputErrResponse(responseBody, &stdout, &stderr)

		log.WithFields(log.Fields{
			LogFieldCommandID: c.id,
			"exit_code":       exitCode,
			"ended":           ended,
		}).Debugf("got %d stderr bytes and %d stdout bytes", stderr.Len(), stdout.Len())
		c.stderr.Write(stderr.Bytes())
		c.stdout.Write(stdout.Bytes())
		if ended {
			logError := false
			if err != nil {
				atomic.AddInt64(&c.errorCount, 1)
				err = fmt.Errorf("error parsing output response for command %s: %w", c.id, err)
				if c.err == nil {
					c.err = err
				} else {
					logError = true
				}
			}
			c.completed(exitCode, err, logError)
			break
		}
		if err != nil {
			if c.err != nil {
				log.WithFields(log.Fields{
					LogFieldCommandID: c.id,
					log.ErrorKey:      c.err.Error(),
				}).Errorf("error parsing output response for command")
			}
			c.err = err
			atomic.AddInt64(&c.errorCount, 1)
		}
	}
}

// Wait slurps output from the remote command's stdout and stderr buffers, and waits for the remote command to terminate.
func (c *Command) Wait() error {
	c.getOutputLoop()
	return c.err
}

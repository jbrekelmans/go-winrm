package winrm

import (
	"context"
	"fmt"
	"io"
	"io/ioutil"
	"mime"
	"net/http"
	"reflect"
	"strings"
	"unsafe"

	zenwinrm "github.com/masterzen/winrm"
	"github.com/masterzen/winrm/soap"
	log "github.com/sirupsen/logrus"
)

const SoapXMLMimeType = "application/soap+xml"

// See init to learn why this exists.
var dummyEndpoint = zenwinrm.NewEndpoint("", 0, true, false, nil, nil, nil, 0)

type Client struct {
	ctx        context.Context
	httpClient *http.Client
	password   string
	zenClient  *zenwinrm.Client
	url        string
	user       string
	zenParams  *zenwinrm.Parameters
}

func NewClient(
	useTLS bool,
	host string,
	port int,
	user, password string,
	httpClient *http.Client,
	ctx context.Context) (*Client, error) {
	c := &Client{
		ctx:        ctx,
		httpClient: httpClient,
		password:   password,
		url:        FormatURL(useTLS, host, port),
		user:       user,
	}
	if c.ctx == nil {
		return nil, fmt.Errorf("ctx must not be nil")
	}
	if c.httpClient == nil {
		c.httpClient = http.DefaultClient
	}
	err := c.init()
	if err != nil {
		return nil, err
	}
	return c, nil
}

// FormatURL formats the HTTP URL for Windows server remote management.
func FormatURL(useTLS bool, host string, port int) string {
	scheme := "http"
	if useTLS {
		scheme = "https"
	}
	return fmt.Sprintf("%s://%s:%d/wsman", scheme, host, port)
}

// See init to learn why this adapter exists.
type zenTransporterAdapter struct {
	client *Client
}

func (t *zenTransporterAdapter) Transport(endpoint *zenwinrm.Endpoint) error {
	return nil
}

func (t *zenTransporterAdapter) Post(zenClient *zenwinrm.Client, request *soap.SoapMessage) (string, error) {
	return t.client.doPost(request)
}

func (c *Client) init() error {
	var err error
	// We now initialize zenClient with a custom transport, reasoning is as follows:
	// 1. winrm unnecessarily creates a http.Client instance for each request: https://github.com/masterzen/winrm/blob/1d17eaf15943ca3554cdebb3b1b10aaa543a0b7e/http.go#L82
	// 2. winrm does not close the response body in the error case: https://github.com/masterzen/winrm/blob/1d17eaf15943ca3554cdebb3b1b10aaa543a0b7e/http.go#L95
	// 3. winrm's check for the response content type is fishy: https://github.com/masterzen/winrm/blob/1d17eaf15943ca3554cdebb3b1b10aaa543a0b7e/http.go#L21
	//    See doPost for a more solid approach.
	c.zenParams = new(zenwinrm.Parameters)
	*c.zenParams = *zenwinrm.DefaultParameters
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

func (c *Client) doPost(request *soap.SoapMessage) (string, error) {
	method := http.MethodPost
	requestString := request.String()
	req, err := http.NewRequestWithContext(c.ctx, method, c.url, strings.NewReader(requestString))
	if err != nil {
		return "", fmt.Errorf("error creating request %s %#v: %w", method, c.url, err)
	}
	req.Header.Set("Content-Type", SoapXMLMimeType+";charset=UTF-8")
	req.SetBasicAuth(c.user, c.password)
	res, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("error doing HTTP request %s %#v: %w", method, c.url, err)
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		var errorInfo strings.Builder
		_, err = io.CopyN(&errorInfo, res.Body, 4*1024)
		if err != nil {
			log.Errorf("error while reading response body of HTTP request %s %#v: %v", method, c.url, err)
		}
		return "", fmt.Errorf("server responded to %s %#v with unexpected HTTP status %d, body prefix: %#v", method, c.url, res.StatusCode, errorInfo.String())
	}
	contentTypeStrings := res.Header["Content-Type"]
	if len(contentTypeStrings) != 1 {
		return "", fmt.Errorf("server responded to %s %#v with HTTP status %d but the response has %d Content-Type headers", method, c.url, res.StatusCode, len(contentTypeStrings))
	}
	mimeType, _, err := mime.ParseMediaType(contentTypeStrings[0])
	if mimeType != SoapXMLMimeType {
		return "", fmt.Errorf("server responded to %s %#v with HTTP status %d but the Content-Type has unexpected mime type %#v", method, c.url, res.StatusCode, mimeType)
	}
	resBodyData, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return "", fmt.Errorf("error while reading response body of HTTP request %s %#v: %w", method, c.url, err)
	}
	// zenwinrm requires a string so we convert from []byte.
	// go defines strings to contain UTF-8 encoded text, but this is not necessarily the case here.
	// This is not a problem however, since zenwinrm reinterpets the string as bytes later on: https://github.com/masterzen/winrm/blob/1d17eaf15943ca3554cdebb3b1b10aaa543a0b7e/shell.go#L19
	return string(resBodyData), nil
}

func getShellID(shell *zenwinrm.Shell) string {
	reflectShellPtr := reflect.ValueOf(shell)
	reflectShell := reflect.Indirect(reflectShellPtr)
	shellIDMember := reflectShell.FieldByName("id")
	ptrToShellIDUnsafe := unsafe.Pointer(shellIDMember.UnsafeAddr())
	ptrToShellID := (*string)(ptrToShellIDUnsafe)
	shellID := *ptrToShellID
	return shellID
}

// The maximum command line size is 8191 as per Microsoft documentation, but this is the maximum size we can pass to
// (*Shell).Execute without getting a command too long error (so it appears there is some internal overhead).
const cmdExeMaxCommandSize = 8157

// CreateShell creates a cmd.exe Shell that can be used to run commands.
func (c *Client) CreateShell() (*Shell, error) {
	zenShell, err := c.zenClient.CreateShell()
	if err != nil {
		return nil, err
	}
	id := getShellID(zenShell)
	zenParams := c.ZenParametersConst()
	request := zenwinrm.NewExecuteCommandRequest(c.URL(), id, "", []string{}, zenParams)
	maxSizeOfCommandWithZeroArguments := min(zenParams.EnvelopeSize-len(request.String()), cmdExeMaxCommandSize)
	return &Shell{
		c:                                 c,
		id:                                id,
		maxSizeOfCommandWithZeroArguments: maxSizeOfCommandWithZeroArguments,
		zenShell:                          zenShell,
	}, nil
}

// URL returns the remote management URL associated with this client.
func (c *Client) URL() string {
	return c.url
}

// ZenParametersConst returns the *"github.com/masterzen/winrm".Parameters associated with this client.
// The value pointed to should not be modified. This function is usefull when creating requests manually to compute
// size bounds (e.g. "github.com/masterzen/winrm".NewExecuteCommandRequest).
func (c *Client) ZenParametersConst() *zenwinrm.Parameters {
	return c.zenParams
}

// Shell is a wrapper for "github.com/masterzen/winrm".Shell
type Shell struct {
	c                                 *Client
	maxSizeOfCommandWithZeroArguments int
	zenShell                          *zenwinrm.Shell
	id                                string
}

// Client returns the *Client associated with this Shell
func (s *Shell) Client() *Client {
	return s.c
}

// Close is a wrapper that calls (*"github.com/masterzen/winrm".Shell).Close on the wrapped *"github.com/masterzen/winrm".Shell
func (s *Shell) Close() error {
	return s.zenShell.Close()
}

// Execute is a wrapper that calls (*"github.com/masterzen/winrm".Shell).Execute on the wrapped *"github.com/masterzen/winrm".Shell
func (s *Shell) Execute(command string, arguments ...string) (*zenwinrm.Command, error) {
	return s.zenShell.Execute(command, arguments...)
}

// ID returns the ID of this Shell
func (s *Shell) ID() string {
	return s.id
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// MaxSizeOfCommandWithZeroArguments returns the maximum length of a command string that can be passed to Execute, if the command has zero
// arguments.
func (s *Shell) MaxSizeOfCommandWithZeroArguments() int {
	return s.maxSizeOfCommandWithZeroArguments
}

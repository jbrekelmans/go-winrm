package soap

import (
	"strings"
	"testing"
)

func Test_EmitCData(t *testing.T) {
	var sb strings.Builder
	err := emitCData(&sb, []byte("as]]>df"))
	if err != nil {
		t.Fatal(err)
	}
	if sb.String() != "<![CDATA[as]]]]><![CDATA[>df]]>" {
		t.Fatal(sb.String())
	}
}

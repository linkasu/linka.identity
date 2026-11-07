package accountmail

import (
	"errors"
	"io"
	"net/textproto"
	"testing"
)

func TestTemporaryRequiresDefiniteNegativeSMTPReply(t *testing.T) {
	for _, test := range []struct {
		err  error
		want bool
	}{
		{nil, false},
		{io.EOF, false},
		{&textproto.Error{Code: 451, Msg: "unclassified"}, false},
		{&DeliveryError{Stage: "recipient", cause: &textproto.Error{Code: 451}}, true},
		{&DeliveryError{Stage: "accept", cause: &textproto.Error{Code: 421}}, true},
		{&DeliveryError{Stage: "accept", Uncertain: true, cause: &textproto.Error{Code: 451}}, false},
		{&DeliveryError{Stage: "recipient", cause: &textproto.Error{Code: 550}}, false},
		{&DeliveryError{Stage: "connect", cause: io.EOF}, false},
		{errors.New("provider unavailable"), false},
	} {
		if got := Temporary(test.err); got != test.want {
			t.Fatalf("temporary=%v want=%v", got, test.want)
		}
	}
}

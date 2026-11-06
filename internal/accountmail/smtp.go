package accountmail

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/quotedprintable"
	"net"
	"net/mail"
	"net/smtp"
	"net/textproto"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// SMTP sends transactional plain-text mail over mandatory STARTTLS.
type SMTP struct {
	Addr, User, Password, From string
	Timeout                    time.Duration
}

func (s SMTP) Send(ctx context.Context, to, subject, body string) error {
	host, message, err := s.prepare(to, subject, body)
	if err != nil {
		return &DeliveryError{Stage: "config", cause: err}
	}
	timeout := s.Timeout
	if timeout <= 0 || timeout > 10*time.Second {
		timeout = 10 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	conn, err := (&net.Dialer{Timeout: timeout}).DialContext(ctx, "tcp", s.Addr)
	if err != nil {
		return &DeliveryError{Stage: "connect", cause: err}
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	deadline, _ := ctx.Deadline()
	if err := conn.SetDeadline(deadline); err != nil {
		return &DeliveryError{Stage: "connect", cause: err}
	}
	client, err := smtp.NewClient(conn, host)
	if err != nil {
		return &DeliveryError{Stage: "greet", cause: err}
	}
	if err := client.StartTLS(&tls.Config{MinVersion: tls.VersionTLS12, ServerName: host}); err != nil {
		return &DeliveryError{Stage: "tls", cause: err}
	}
	if s.User != "" {
		if err := client.Auth(smtp.PlainAuth("", s.User, s.Password, host)); err != nil {
			return &DeliveryError{Stage: "auth", cause: err}
		}
	}
	return submit(client, s.From, to, message)
}

func (s SMTP) prepare(to, subject, body string) (string, []byte, error) {
	host, port, err := net.SplitHostPort(s.Addr)
	if err != nil || host == "" || port == "" {
		return "", nil, errors.New("invalid SMTP address")
	}
	if (s.User == "") != (s.Password == "") {
		return "", nil, errors.New("incomplete SMTP credentials")
	}
	for _, address := range []string{s.From, to} {
		if strings.IndexFunc(address, unicode.IsControl) >= 0 {
			return "", nil, errors.New("invalid mailbox")
		}
		parsed, err := mail.ParseAddress(address)
		if err != nil || parsed.Name != "" || parsed.Address != address {
			return "", nil, errors.New("invalid mailbox")
		}
	}
	if !utf8.ValidString(subject) || subject == "" || utf8.RuneCountInString(subject) > 200 || strings.ContainsAny(subject, "\r\n\x00") {
		return "", nil, errors.New("invalid subject")
	}
	if !utf8.ValidString(body) || len(body) > 64*1024 {
		return "", nil, errors.New("invalid body")
	}
	var message bytes.Buffer
	fmt.Fprintf(&message, "From: %s\r\nTo: %s\r\nSubject: %s\r\nDate: %s\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\n",
		s.From, to, mime.QEncoding.Encode("UTF-8", subject), time.Now().Format(time.RFC1123Z))
	w := quotedprintable.NewWriter(&message)
	if _, err := io.WriteString(w, body); err != nil {
		return "", nil, err
	}
	if err := w.Close(); err != nil {
		return "", nil, err
	}
	return host, message.Bytes(), nil
}

// DeliveryError reports a sanitized stage and whether delivery may have occurred.
type DeliveryError struct {
	Stage     string
	Uncertain bool
	cause     error
}

func (e *DeliveryError) Error() string {
	switch e.Stage {
	case "config", "connect", "greet", "tls", "auth", "mail", "recipient", "data", "write", "accept":
		return "account mail: " + e.Stage + " failed"
	default:
		return "account mail: delivery failed"
	}
}
func (e *DeliveryError) Unwrap() error { return e.cause }

// Uncertain is conservative for errors from unknown senders.
func Uncertain(err error) bool {
	if err == nil {
		return false
	}
	var delivery *DeliveryError
	if errors.As(err, &delivery) && delivery != nil {
		return delivery.Uncertain
	}
	return true
}

type smtpSubmission interface {
	Mail(string) error
	Rcpt(string) error
	Data() (io.WriteCloser, error)
	Quit() error
	Close() error
}

func submit(client smtpSubmission, from, to string, message []byte) error {
	defer client.Close()
	if err := client.Mail(from); err != nil {
		return &DeliveryError{Stage: "mail", cause: err}
	}
	if err := client.Rcpt(to); err != nil {
		return &DeliveryError{Stage: "recipient", cause: err}
	}
	w, err := client.Data()
	if err != nil {
		return &DeliveryError{Stage: "data", cause: err}
	}
	if _, err := io.Copy(w, bytes.NewReader(message)); err != nil {
		// Do not finish a partial message by closing the dot writer.
		return dataError("write", err)
	}
	if err := w.Close(); err != nil {
		return dataError("accept", err)
	}
	// DATA acceptance is final; QUIT failure cannot make retry safe.
	_ = client.Quit()
	return nil
}

func dataError(stage string, err error) error {
	var rejection *textproto.Error
	definite := errors.As(err, &rejection) && rejection != nil && rejection.Code >= 400 && rejection.Code <= 599
	return &DeliveryError{Stage: stage, Uncertain: !definite, cause: err}
}

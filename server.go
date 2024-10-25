package pop3

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"io"
	"net/textproto"
	"strconv"
	"strings"
)

const (
	POP3User       = "USER"
	POP3Pass       = "PASS"
	POP3StartTLS   = "STLS"
	POP3Capability = "CAPA"
	POP3Status     = "STAT"
	POP3List       = "LIST"
	POP3UIDList    = "UIDL"
	POP3Retrieve   = "RETR"
	POP3Delete     = "DELE"
	POP3Noop       = "NOOP"
	POP3Reset      = "RSET"
	POP3Quit       = "QUIT"
)

var (
	ErrInvalidAuthorizer = errors.New("pop3: Missing authorizer")
	ErrServerClosed      = errors.New("pop3: Server closed")
)

// Authorizer responds to a POP3 AUTHORIZATION state request.
type Authorizer[MailID StringyIdentifier] interface {
	Auth(ctx context.Context, user, pass string) (Maildropper[MailID], error)
}

type StringyIdentifier interface {
	cmp.Ordered

	String() string
}

type MailInfo[MailID StringyIdentifier] struct {
	ID   MailID
	Size uint64
}

// Maildropper responds to a POP3 TRANSACTION state requests.
type Maildropper[MailID StringyIdentifier] interface {
	List(ctx context.Context) ([]MailInfo[MailID], error)

	Get(ctx context.Context, key MailID) (io.Reader, error)
	Delete(ctx context.Context, key MailID) error
}

type ServeOptions[MailID StringyIdentifier] struct {
	Authorizer Authorizer[MailID]
	Banner     string
}

// ServeConn serves POP3 using the provided connection. It blocks until the connection is closed.
func ServeConn[MailID StringyIdentifier](ctx context.Context, rwc io.ReadWriteCloser, opts ServeOptions[MailID]) error {
	c := conn[MailID]{rwc: rwc, text: textproto.NewConn(rwc), opts: opts}

	c.serve(ctx)

	return nil
}

// A conn represents the server side of an POP3 connection.
type conn[MailID StringyIdentifier] struct {
	// rwc is the underlying network connection.
	// This is never wrapped by other types and is the value given out
	// to CloseNotifier callers. It is usually of type *net.TCPConn or
	// *tls.Conn.
	rwc io.ReadWriteCloser

	// text is the textproto.Conn used by the Client.
	text *textproto.Conn

	opts ServeOptions[MailID]
}

func (c *conn[MailID]) serve(ctx context.Context) {
	defer c.rwc.Close()

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	if err := c.text.PrintfLine("+OK %s", c.opts.Banner); err != nil {
		return
	}

	c.auth(ctx, c.opts.Authorizer)
}

func (c *conn[MailID]) scan() (string, string, error) {
	l, err := c.text.ReadLine()
	if err != nil {
		return "", "", fmt.Errorf("unable to read line: %w", err)
	}

	var cmd string
	var arg string

	part := strings.SplitN(l, " ", 2)
	cmd = strings.ToUpper(part[0])
	arg = ""
	if len(part) > 1 {
		arg = part[1]
	}

	return cmd, arg, nil
}

func (c *conn[MailID]) Ok(format string, args ...interface{}) error {
	if err := c.text.PrintfLine("+OK "+format, args...); err != nil {
		return fmt.Errorf("unable to send OK response: %w", err)
	}

	return nil
}

func (c *conn[MailID]) Err(format string, args ...interface{}) error {
	if err := c.text.PrintfLine("-ERR "+format, args...); err != nil {
		return fmt.Errorf("unable to send ERR response: %w", err)
	}

	return nil
}

func (c *conn[MailID]) auth(ctx context.Context, auth Authorizer[MailID]) error {
	var user string
	var pass string

	for {
		cmd, arg, err := c.scan()
		if err != nil {
			return err
		}

		switch cmd {
		case POP3User, POP3Pass:
			switch cmd {
			case POP3User:
				user = arg
			case POP3Pass:
				pass = arg
			}

			if user != "" && pass != "" {
				m, err := auth.Auth(ctx, user, pass)
				if err != nil {
					if err := c.Err("invalid password"); err != nil {
						return fmt.Errorf("unable to send invalid password response: %w", err)
					}

					continue
				}

				return c.process(ctx, m)
			}

			c.Ok("send PASS")

		case POP3StartTLS:
			if err := c.Err("StartTLS not supported"); err != nil {
				return fmt.Errorf("unable to send StartTLS not supported response: %w", err)
			}

			continue

		case POP3Capability:
			if err := c.Ok("Capability list follows"); err != nil {
				return fmt.Errorf("unable to send Capability list follows response: %w", err)
			}
			if err := c.text.PrintfLine("USER"); err != nil {
				return fmt.Errorf("unable to send USER capability: %w", err)
			}
			if err := c.text.PrintfLine("IMPLEMENTATION %s", c.opts.Banner); err != nil {
				return fmt.Errorf("unable to send IMPLEMENTATION capability: %w", err)
			}

			if err := c.text.PrintfLine("."); err != nil {
				return fmt.Errorf("unable to send end of capability list: %w", err)
			}

		case POP3Quit:
			if err := c.text.PrintfLine("+OK bye"); err != nil {
				return fmt.Errorf("unable to send OK bye response: %w", err)
			}

			return nil

		default:
			c.Err("malformed command")
		}
	}
}

func sendMailList[MailID StringyIdentifier](tp *textproto.Conn, mailinfos []MailInfo[MailID], stringer func(mi MailInfo[MailID]) string) {

}

func (c *conn[MailID]) process(ctx context.Context, maildrop Maildropper[MailID]) error {
	var total uint64 // total messages size

	// set of messages marked for deleteion
	deleted := make(map[int]struct{})

	sizes, err := maildrop.List(ctx)
	if err != nil {
		if err := c.Err("maildrop locked"); err != nil {
			return fmt.Errorf("unable to send maildrop locked response: %w", err)
		}

		return err
	}

	for _, v := range sizes {
		total += v.Size
	}

	c.Ok("welcome home")

	for {
		cmd, arg, err := c.scan()
		if err != nil {
			return err
		}

		switch cmd {
		case POP3Noop:
			c.Ok("")

		case POP3Status:
			c.Ok("%d %d", len(sizes), total)

		case POP3List:
			if arg == "" {
				if err := c.Ok("%d messages (%d octets)", len(sizes), total); err != nil {
					return err
				}
				for i, v := range sizes {
					if _, ok := deleted[i]; ok {
						continue
					}

					if err := c.text.PrintfLine("%d %d", i, v.Size); err != nil {
						return fmt.Errorf("unable to send LIST response: %w", err)
					}
				}

				if err := c.text.PrintfLine("."); err != nil {
					return fmt.Errorf("unable to send end of LIST response: %w", err)
				}

				continue
			}

			n, err := strconv.Atoi(arg)
			if err != nil {
				if err := c.Err("invalid argument"); err != nil {
					return fmt.Errorf("unable to send invalid argument response: %w", err)
				}

				continue
			}

			if _, ok := deleted[n]; ok {
				if err := c.Err("message deleted"); err != nil {
					return fmt.Errorf("unable to send message deleted response: %w", err)
				}

				continue
			}

			if len(sizes) < n || n < 0 {
				if err := c.Err("unknown message"); err != nil {
					return fmt.Errorf("unable to send unknown message response: %w", err)
				}
			}

			if err := c.Ok("%d %d", n, sizes[n].Size); err != nil {
				return fmt.Errorf("unable to send LIST response: %w", err)
			}

		case POP3Retrieve:
			n, err := strconv.Atoi(arg)
			if err != nil {
				if err := c.Err("invalid argument"); err != nil {
					return fmt.Errorf("unable to send invalid argument response: %w", err)
				}

				continue
			}

			if _, ok := deleted[n]; ok {
				if err := c.Err("message deleted"); err != nil {
					return fmt.Errorf("unable to send message deleted response: %w", err)
				}

				continue
			}

			if len(sizes) < n || n < 0 {
				if err := c.Err("unknown message"); err != nil {
					return fmt.Errorf("unable to send unknown message response: %w", err)
				}

				continue
			}

			if err := c.Ok("%d octets", sizes[n].Size); err != nil {
				return fmt.Errorf("unable to send octets response: %w", err)
			}

			r, err := maildrop.Get(ctx, sizes[n].ID)
			if err != nil {
				if err := c.Err("no such message"); err != nil {
					return fmt.Errorf("unable to send no such message response: %w", err)
				}

				continue
			}

			dw := c.text.DotWriter()

			if _, err := io.Copy(dw, r); err != nil {
				dw.Close()

				return fmt.Errorf("unable to copy message to client: %w", err)
			}

			dw.Close()

			if rc, ok := r.(io.Closer); ok {
				rc.Close()
			}

		case POP3Delete:
			n, err := strconv.Atoi(arg)
			if err != nil {
				if err := c.Err("invalid argument"); err != nil {
					return fmt.Errorf("unable to send invalid argument response: %w", err)
				}

				continue
			}
			if len(sizes) < n || n < 0 {
				if err := c.Err("unknown message"); err != nil {
					return fmt.Errorf("unable to send unknown message response: %w", err)
				}
			}

			deleted[n] = struct{}{}
			if err := c.Ok("message %d deleted", n); err != nil {
				return fmt.Errorf("unable to send message deleted response: %w", err)
			}

		case POP3Reset:
			n, err := strconv.Atoi(arg)
			if err != nil {
				if err := c.Err("invalid argument"); err != nil {
					return fmt.Errorf("unable to send invalid argument response: %w", err)
				}

				continue
			}

			if _, ok := deleted[n]; !ok {
				c.Err("RSET _what_?")
				continue
			}
			delete(deleted, n)
			c.Ok("")

		case POP3Quit:
			for k := range deleted {
				if err := maildrop.Delete(ctx, sizes[k].ID); err != nil {
					if err := c.Err("oops"); err != nil {
						return fmt.Errorf("unable to send oops response: %w", err)
					}
				}
			}

			if err := c.Ok("bye"); err != nil {
				return fmt.Errorf("unable to send bye response: %w", err)
			}

			return nil

		default:
			c.Err("malformed command")
		}
	}
}

package main

import (
	"context"
	"io"
	"log"
	"net"
	"strconv"
	"strings"

	"github.com/thriqon/pop3"
)

type mailidentifier int64

func (m mailidentifier) String() string {
	return strconv.Itoa(int(m))
}

type authorizer struct {
}

func (a authorizer) Auth(ctx context.Context, user, pass string) (pop3.Maildropper[mailidentifier], error) {
	if user == "admin" && pass == "pass" {
		return &memoryMaildropper{}, nil
	}
	return nil, nil
}

type memoryMaildropper struct {
}

func (m memoryMaildropper) List(ctx context.Context) ([]pop3.MailInfo[mailidentifier], error) {
	return []pop3.MailInfo[mailidentifier]{
		{ID: 1, Size: 100},
		{ID: 2, Size: 200},
	}, nil
}

func (m memoryMaildropper) Get(ctx context.Context, key mailidentifier) (io.Reader, error) {
	return strings.NewReader("Hello, World!"), nil
}

func (m memoryMaildropper) Delete(ctx context.Context, key mailidentifier) error {
	return nil
}

func main() {
	ln, err := net.Listen("tcp", ":11000")
	if err != nil {
		log.Fatalln(err)
	}

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Println(err)
			continue
		}

		go pop3.ServeConn(context.Background(), conn, pop3.ServeOptions[mailidentifier]{
			Authorizer: &authorizer{},
			Banner:     "memory-pop3",
		})
	}
}

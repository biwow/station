package tool

import (
	"bufio"
	"errors"
	"io"
	"net"
)

var (
	ErrNotEnough = errors.New("not enough")
)

type ReadBuffer struct {
	reader io.Reader
	buf    []byte
	start  int
	end    int
}

func NewBuffer(conn net.Conn, len int) ReadBuffer {
	reader := bufio.NewReader(conn)
	buf := make([]byte, len)
	return ReadBuffer{reader, buf, 0, 0}
}

func (b *ReadBuffer) len() int {
	return b.end - b.start
}

// Grow 将有用的字节前移
func (b *ReadBuffer) grow() {
	if b.start == 0 {
		return
	}
	copy(b.buf, b.buf[b.start:b.end])
	b.end -= b.start
	b.start = 0
}

// ReadFromReader 从reader里面读取数据，如果reader阻塞，会发生阻塞
func (b *ReadBuffer) ReadFromReader() (int, error) {
	b.grow()
	n, err := b.reader.Read(b.buf[b.end:])
	if err != nil {
		return n, err
	}
	if n == 0 {
		return n, ErrNotEnough
	}
	b.end += n
	return n, nil
}

// Seek 返回n个字节，而不产生移位，如果没有足够字节，返回错误
func (b *ReadBuffer) Seek(start, end int) ([]byte, error) {
	if b.end-b.start >= end-start {
		buf := b.buf[b.start+start : b.start+end]
		return buf, nil
	}
	return nil, ErrNotEnough
}

// read 舍弃offset个字段，读取n个字段,如果没有足够的字节，返回错误
func (b *ReadBuffer) Read(offset, limit int) ([]byte, error) {
	if b.len() < offset+limit {
		return nil, ErrNotEnough
	}
	b.start += offset
	buf := b.buf[b.start : b.start+limit]
	b.start += limit
	return buf, nil
}

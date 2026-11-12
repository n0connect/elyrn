package agent

import (
	"bufio"
	"bytes"
	"errors"
	"io"
)

// maxDiscardChunks bounds how much of an overlong line is skipped (RULES.md §8.1).
const maxDiscardChunks = 1 << 20

// ErrLineTooLong reports a line longer than the reader's buffer; the rest of it was discarded.
var ErrLineTooLong = errors.New("agent: line too long")

// ReadBoundedLine returns the next line without its "\n" or "\r\n", at most the reader's buffer
// size long: one helper for both line protocols (MCP on stdin, SSE from the server). A last
// line without a newline is returned with a nil error; io.EOF follows it.
func ReadBoundedLine(r *bufio.Reader) ([]byte, error) {
	line, err := r.ReadSlice('\n')
	switch {
	case errors.Is(err, bufio.ErrBufferFull):
		return nil, discardLine(r)
	case errors.Is(err, io.EOF) && len(line) > 0:
		err = nil
	case err != nil:
		return nil, err
	}
	line = bytes.TrimSuffix(bytes.TrimSuffix(line, []byte("\n")), []byte("\r"))
	return append([]byte(nil), line...), err
}

// discardLine skips to the end of the current line and reports it as too long.
func discardLine(r *bufio.Reader) error {
	for chunk := 0; chunk < maxDiscardChunks; chunk++ {
		_, err := r.ReadSlice('\n')
		if errors.Is(err, bufio.ErrBufferFull) {
			continue
		}
		if err != nil && !errors.Is(err, io.EOF) {
			return err
		}
		return ErrLineTooLong
	}
	return ErrLineTooLong
}

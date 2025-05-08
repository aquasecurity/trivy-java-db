package index

import (
	"encoding/csv"
	"io"
	"os"
)

const NotAvailable = "N/A"

type Reader struct {
	f *os.File
	csv.Reader
}

func Open(path string) (*Reader, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}

	return &Reader{
		f:      f,
		Reader: *newCSVReader(f),
	}, nil
}

func NewReader(r io.Reader) *Reader {
	return &Reader{
		Reader: *newCSVReader(r),
	}
}

func newCSVReader(r io.Reader) *csv.Reader {
	reader := csv.NewReader(r)
	reader.Comma = '\t' // Use tab as delimiter
	reader.FieldsPerRecord = 5
	reader.ReuseRecord = true // Reuse memory for performance
	return reader
}

func (r *Reader) Close() error {
	if r.f == nil {
		return nil
	}
	return r.f.Close()
}

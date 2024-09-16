package tool

import "testing"

func TestValidateCP(t *testing.T) {
	ok := ValidateCP("TLV")
	t.Log(ok)
}

func TestValidateTP(t *testing.T) {
	ok := ValidateTP("TCP1")
	t.Log(ok)
}

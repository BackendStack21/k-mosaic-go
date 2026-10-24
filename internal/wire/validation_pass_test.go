package wire

import "testing"

func TestReaderLVLeavesOffsetOnFailure(t *testing.T) {
	data := AppendLV(nil, []byte("abc"))
	r := NewReader(data)
	if _, err := r.LV(2); err == nil {
		t.Fatal("over-long field accepted")
	}
	if r.Done() == nil {
		t.Fatal("Done succeeded after a failed read: the length prefix was consumed")
	}
	if v, err := r.LV(3); err != nil || string(v) != "abc" || r.Done() != nil {
		t.Fatalf("field unreadable after a failed attempt: %v %q", err, v)
	}
	if _, err := NewReader(data).LV(-1); err == nil {
		t.Fatal("negative maxLen accepted")
	}
	var nilReader *Reader
	if nilReader.Done() == nil {
		t.Fatal("nil reader reported done")
	}
}

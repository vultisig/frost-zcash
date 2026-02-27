package frost

import (
	"encoding/binary"
	"fmt"
)

type MapEntry struct {
	ID    []byte
	Value []byte
}

func EncodeMap(entries []MapEntry) []byte {
	buf := make([]byte, 4)
	binary.LittleEndian.PutUint32(buf, uint32(len(entries)))
	for _, e := range entries {
		klen := make([]byte, 4)
		binary.LittleEndian.PutUint32(klen, uint32(len(e.ID)))
		buf = append(buf, klen...)
		buf = append(buf, e.ID...)
		vlen := make([]byte, 4)
		binary.LittleEndian.PutUint32(vlen, uint32(len(e.Value)))
		buf = append(buf, vlen...)
		buf = append(buf, e.Value...)
	}
	return buf
}

func DecodeMap(data []byte) ([]MapEntry, error) {
	if len(data) < 4 {
		return nil, fmt.Errorf("frost: codec: data too short")
	}
	count := int(binary.LittleEndian.Uint32(data[:4]))
	pos := 4
	entries := make([]MapEntry, 0, count)
	for i := 0; i < count; i++ {
		if pos+4 > len(data) {
			return nil, fmt.Errorf("frost: codec: truncated at key length %d", i)
		}
		klen := int(binary.LittleEndian.Uint32(data[pos : pos+4]))
		pos += 4
		if pos+klen > len(data) {
			return nil, fmt.Errorf("frost: codec: truncated at key data %d", i)
		}
		key := make([]byte, klen)
		copy(key, data[pos:pos+klen])
		pos += klen

		if pos+4 > len(data) {
			return nil, fmt.Errorf("frost: codec: truncated at value length %d", i)
		}
		vlen := int(binary.LittleEndian.Uint32(data[pos : pos+4]))
		pos += 4
		if pos+vlen > len(data) {
			return nil, fmt.Errorf("frost: codec: truncated at value data %d", i)
		}
		val := make([]byte, vlen)
		copy(val, data[pos:pos+vlen])
		pos += vlen

		entries = append(entries, MapEntry{ID: key, Value: val})
	}
	return entries, nil
}

package VHtearCryptoutil

//Made with the happiness of VHtear

import (
	"encoding/binary"
)

func GetIntBytesV2(i int) []byte {
	j := 4
	isCompact := false
	if isCompact {
		var a = int32(i)
		if j*j == 16 {
			a = int32(i)
		} else {
			a = int32(i)
		}

		a = (a << 1) ^ (a >> 31)
		var b []byte
		for a >= 0x80 {
			b = append(b, byte(a)|0x80)
			a >>= 7
		}
		b = append(b, byte(a))
		return b
	}

	res := make([]byte, j)
	if j*j == 16 {
		binary.BigEndian.PutUint32(res, uint32(i))
	} else {
		binary.BigEndian.PutUint64(res, uint64(i))
	}
	return res
}

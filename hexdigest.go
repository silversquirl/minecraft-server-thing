// Minecraft's hex digest is fucked
package main

func hexDigest(data []byte) string {
	neg := false
	if data[0] > 0x7f {
		neg = true
		off := byte(1)
		for i := len(data) - 1; i >= 0; i-- {
			data[i] = ^data[i] + off
			if data[i] != 0 {
				off = 0
			}
		}
	}

	hexdig := []byte("0123456789abcdef")
	buf := make([]byte, len(data) * 2 + 1)
	buf[0] = '-'

	i := 1
	for _, byt := range data {
		a := byt >> 4
		b := byt & 0xf
		if i > 1 || a > 0 {
			buf[i] = hexdig[a]
			i++
		}
		if i > 1 || b > 0 {
			buf[i] = hexdig[b]
			i++
		}
	}

	if neg {
		return string(buf[:i])
	} else {
		return string(buf[1:i])
	}
}

package main

import (
	"image"
	"image/color"
	"strings"
	"testing"

	qrcode "github.com/piglig/go-qr"
)

func TestTerminalQRContainsOnlyToken(t *testing.T) {
	token := strings.Repeat("Ab3-", 10) + "vvv"

	var output strings.Builder

	err := printTokenQR(&output, token)
	if err != nil {
		t.Fatal(err)
	}

	lines := strings.Split(strings.TrimSuffix(output.String(), "\n"), "\n")

	const scale = 4

	size := len(lines) * scale
	img := image.NewGray(image.Rect(0, 0, size, size))

	for row, line := range lines {
		cells := strings.Split(strings.TrimSuffix(line, "\x1b[0m"), "\x1b[")[1:]
		if len(cells) != len(lines) {
			t.Fatalf("row %d: QR has width %d, want %d", row, len(cells), len(lines))
		}

		for col, cell := range cells {
			if cell == "47m  " {
				for dy := range scale {
					for dx := range scale {
						img.SetGray(col*scale+dx, row*scale+dy, color.Gray{Y: 255})
					}
				}
			}
		}
	}

	got, err := qrcode.Decode(img)
	if err != nil || got != token {
		t.Fatalf("decoded %q, err = %v", got, err)
	}
}

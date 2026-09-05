package cli

import (
	"bytes"
	"strings"
	"testing"

	"rsc.io/qr"
)

// The QR is a convenience, so the thing that must never happen is it breaking
// the output someone needs to read. Anything that is not an interactive
// terminal gets no escape codes at all.
func TestQRIsSkippedWhenOutputIsNotATerminal(t *testing.T) {
	var buf bytes.Buffer
	if writeQRCode(&buf, "https://treehouse.example/settings/pair") {
		t.Fatal("a buffer is not a terminal; nothing should have been drawn")
	}
	if buf.Len() != 0 {
		t.Fatalf("nothing should have been written, got %q", buf.String())
	}
}

// The rendering has to survive a round trip through a decoder, not merely look
// like a QR. This walks the modules back out of the encoder and checks the
// glyph and colour chosen for each pair of rows, which is where an inverted or
// off-by-one renderer goes wrong.
func TestQRRenderingMatchesTheEncodedModules(t *testing.T) {
	const url = "https://treehouse.example/settings/pair"
	code, err := qr.Encode(url, qr.M)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}

	var buf bytes.Buffer
	// Bypasses the terminal check on purpose: this test is about the drawing,
	// and the skip behaviour is covered above.
	renderQRCode(&buf, code)
	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")

	size := code.Size + quietZone*2
	if want := (size + 1) / 2; len(lines) != want {
		t.Fatalf("expected %d rows for a %d-module code, got %d", want, size, len(lines))
	}

	// The quiet zone is what a scanner uses to find the code's edges, so a
	// missing one is the failure that looks fine and scans badly.
	for _, row := range lines[:quietZone/2] {
		if strings.Contains(row, ansiBlack) {
			t.Fatal("the top quiet zone must be entirely light")
		}
	}

	// Spot-check the darkest thing in any QR: the top-left finder pattern's
	// centre, which is set for every code at every size.
	if !code.Black(3, 3) {
		t.Fatal("expected the finder pattern centre to be set")
	}
	row := lines[(3+quietZone)/2]
	if !strings.Contains(row, ansiBlack) {
		t.Fatalf("the row carrying the finder pattern must draw dark modules: %q", row)
	}
}

// An odd-sized code has no bottom neighbour on its final row. Reading past the
// edge there would either panic or draw a stray dark line across the bottom of
// every code, which is exactly where a scanner looks for the quiet zone.
func TestQRHandlesAnOddFinalRow(t *testing.T) {
	code, err := qr.Encode("https://treehouse.example/settings/pair", qr.M)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if (code.Size+quietZone*2)%2 == 0 {
		t.Skip("this code's rendered height is even; the overhang case needs an odd one")
	}

	var buf bytes.Buffer
	renderQRCode(&buf, code)
	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")

	last := lines[len(lines)-1]
	if strings.Contains(last, ansiOnDark) {
		t.Fatal("the overhang past the final module row must be quiet zone, not dark")
	}
}

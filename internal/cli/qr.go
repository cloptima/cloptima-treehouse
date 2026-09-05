package cli

import (
	"fmt"
	"io"
	"os"
	"strings"

	"rsc.io/qr"
)

// Rendering a QR code into a terminal, so someone connecting a headless host
// can point a phone at it instead of retyping a URL.
//
// The QR carries the verification URL and nothing else. It deliberately does
// not carry the user code: RFC 8628 §5.4 warns against pre-filling it, because
// a link that arrives already carrying a code turns approval into one tap for
// whoever sends it. The code stays a thing a person reads and types.

const (
	// quietZone is the mandatory light border. Four modules is what the spec
	// asks for; without it a scanner sitting on a dark terminal often cannot
	// find the code's edges at all.
	quietZone = 4

	// Half blocks let one text row carry two module rows, which is what keeps
	// a ~33-module code inside a normal terminal window.
	upperHalfBlock = "▀"

	// Explicit colours rather than relying on the terminal's own foreground.
	// A QR has to be dark-on-light to scan reliably, and a terminal may be
	// themed either way -- inheriting its colours would produce an inverted
	// code on the dark themes most servers are read on.
	ansiReset   = "\x1b[0m"
	ansiWhite   = "\x1b[38;5;15m"
	ansiOnDark  = "\x1b[48;5;0m"
	ansiBlack   = "\x1b[38;5;0m"
	ansiOnLight = "\x1b[48;5;15m"
)

// writeQRCode renders url as a scannable block, or returns false if it cannot.
//
// Returning false rather than printing something broken matters: the URL and
// the code are printed either way, so a terminal that cannot render this loses
// a convenience, not the ability to pair.
func writeQRCode(out io.Writer, url string) bool {
	if !supportsANSI(out) {
		return false
	}
	// Medium recovery: a terminal is a clean, high-contrast display, so the
	// redundancy that helps on a creased sticker only makes the code denser
	// and harder to fit on screen here.
	code, err := qr.Encode(url, qr.M)
	if err != nil {
		return false
	}
	renderQRCode(out, code)
	return true
}

// renderQRCode is the drawing, split from the terminal check so a test can
// exercise it without pretending to be a TTY.
func renderQRCode(out io.Writer, code *qr.Code) {
	size := code.Size + quietZone*2
	var b strings.Builder
	// Two module rows per text row, so a light bottom half is the background
	// colour and a light top half is the glyph.
	for y := 0; y < size; y += 2 {
		for x := 0; x < size; x++ {
			topLight := !isDark(code, x-quietZone, y-quietZone)
			// An odd-height code's final row has no bottom neighbour; treat
			// the overhang as quiet zone rather than reading past the edge.
			bottomLight := !isDark(code, x-quietZone, y+1-quietZone)

			if bottomLight {
				b.WriteString(ansiOnLight)
			} else {
				b.WriteString(ansiOnDark)
			}
			if topLight {
				b.WriteString(ansiWhite)
			} else {
				b.WriteString(ansiBlack)
			}
			b.WriteString(upperHalfBlock)
		}
		b.WriteString(ansiReset)
		b.WriteString("\n")
	}

	fmt.Fprint(out, b.String())
}

// isDark reports whether a module is set, treating anything outside the code
// as light so the quiet zone falls out of the same lookup.
func isDark(code *qr.Code, x, y int) bool {
	if x < 0 || y < 0 || x >= code.Size || y >= code.Size {
		return false
	}
	return code.Black(x, y)
}

// supportsANSI reports whether escape codes will be read as colour rather than
// printed as noise. A piped or redirected stream gets no QR: half the point of
// `treehouse pair` is that its output is readable in a log or over SSH.
func supportsANSI(out io.Writer) bool {
	if os.Getenv("NO_COLOR") != "" || os.Getenv("TERM") == "dumb" {
		return false
	}
	file, ok := out.(*os.File)
	if !ok {
		return false
	}
	info, err := file.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}

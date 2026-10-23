//go:build windows

package main

import (
	"bytes"
	"context"
	_ "embed"
	"fmt"
	"image/png"
	"runtime"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
	"unicode/utf16"
	"unsafe"
)

//go:embed assets/allow.png
var allowPNG []byte

//go:embed assets/block.png
var blockPNG []byte

var (
	k32   = syscall.NewLazyDLL("kernel32.dll")
	u32   = syscall.NewLazyDLL("user32.dll")
	g32   = syscall.NewLazyDLL("gdi32.dll")
	msimg = syscall.NewLazyDLL("msimg32.dll")

	pSetDefaultDllDirs = k32.NewProc("SetDefaultDllDirectories")
	pGetModuleHandle   = k32.NewProc("GetModuleHandleW")

	pRegisterClass  = u32.NewProc("RegisterClassExW")
	pCreateWindowEx = u32.NewProc("CreateWindowExW")
	pDefWindowProc  = u32.NewProc("DefWindowProcW")
	pShowWindow     = u32.NewProc("ShowWindow")
	pGetMessage     = u32.NewProc("GetMessageW")
	pTranslateMsg   = u32.NewProc("TranslateMessage")
	pDispatchMsg    = u32.NewProc("DispatchMessageW")
	pPostQuit       = u32.NewProc("PostQuitMessage")
	pPostMessage    = u32.NewProc("PostMessageW")
	pSendMessage    = u32.NewProc("SendMessageW")
	pBeginPaint     = u32.NewProc("BeginPaint")
	pEndPaint       = u32.NewProc("EndPaint")
	pGetClientRect  = u32.NewProc("GetClientRect")
	pInvalidate     = u32.NewProc("InvalidateRect")
	pFillRect       = u32.NewProc("FillRect")
	pDrawText       = u32.NewProc("DrawTextW")
	pLoadCursor     = u32.NewProc("LoadCursorW")
	pLoadImage      = u32.NewProc("LoadImageW")
	pDrawIconEx     = u32.NewProc("DrawIconEx")
	pGetWindowText  = u32.NewProc("GetWindowTextW")
	pSetWindowText  = u32.NewProc("SetWindowTextW")
	pEnableWindow   = u32.NewProc("EnableWindow")
	pSetFocus       = u32.NewProc("SetFocus")
	pSetCapture     = u32.NewProc("SetCapture")
	pReleaseCapture = u32.NewProc("ReleaseCapture")
	pGetSysMetrics  = u32.NewProc("GetSystemMetrics")
	pScreenToClient = u32.NewProc("ScreenToClient")
	pGetDC          = u32.NewProc("GetDC")
	pReleaseDC      = u32.NewProc("ReleaseDC")
	pGetKeyState    = u32.NewProc("GetKeyState")

	pCreateCompatDC  = g32.NewProc("CreateCompatibleDC")
	pCreateCompatBmp = g32.NewProc("CreateCompatibleBitmap")
	pSelectObject    = g32.NewProc("SelectObject")
	pDeleteObject    = g32.NewProc("DeleteObject")
	pDeleteDC        = g32.NewProc("DeleteDC")
	pBitBlt          = g32.NewProc("BitBlt")
	pCreateBrush     = g32.NewProc("CreateSolidBrush")
	pCreateFont      = g32.NewProc("CreateFontW")
	pSetBkMode       = g32.NewProc("SetBkMode")
	pSetTextColor    = g32.NewProc("SetTextColor")
	pGetDeviceCaps   = g32.NewProc("GetDeviceCaps")
	pCreateDIB       = g32.NewProc("CreateDIBSection")
	pAlphaBlend      = msimg.NewProc("AlphaBlend")
)

type wndclassex struct {
	Size, Style          uint32
	WndProc              uintptr
	ClsExtra, WndExtra   int32
	Instance, Icon, Curs uintptr
	Background           uintptr
	MenuName, ClassName  *uint16
	IconSm               uintptr
}
type point struct{ X, Y int32 }
type rect struct{ L, T, R, B int32 }
type winmsg struct {
	Hwnd    uintptr
	Message uint32
	WParam  uintptr
	LParam  uintptr
	Time    uint32
	Pt      point
}
type paintstruct struct {
	Hdc       uintptr
	Erase     int32
	Rc        rect
	Restore   int32
	IncUpdate int32
	Rsv       [32]byte
}
type bmih struct {
	Size           uint32
	W, H           int32
	Planes, BitCnt uint16
	Compression    uint32
	SizeImage      uint32
	XPels, YPels   int32
	ClrUsed, ClrIm uint32
}

const (
	wmDestroy, wmPaint, wmEraseBkgnd, wmActivate = 0x2, 0xF, 0x14, 0x6
	wmClose, wmSetFont, wmCommand, wmNcHitTest   = 0x10, 0x30, 0x111, 0x84
	wmKeyDown, wmLButtonDown, wmLButtonUp        = 0x100, 0x201, 0x202
	wmApp                                        = 0x8000 + 1
	emSetSel, emLimitText                        = 0xB1, 0xC5

	wsPopup, wsMinBox, wsSysMenu, wsClipKids = 0x80000000, 0x20000, 0x80000, 0x2000000
	wsChild, wsVisible, wsTabStop            = 0x40000000, 0x10000000, 0x10000
	esAutoHScroll, bsDefPush                 = 0x80, 0x1
	wsExClientEdge, wsExAppWindow            = 0x200, 0x40000

	idCheck                 = 1
	vkReturn, vkTab, vkCtrl = 0x0D, 0x09, 0x11

	dtCenter, dtRight, dtVCenter, dtSingle = 0x1, 0x2, 0x4, 0x20
	dtWordBreak, dtNoPrefix, dtEllipsis    = 0x10, 0x800, 0x8000
)

// logical (96 dpi) layout
const (
	winW, winH = 640, 602
	frame      = 4
	titleH     = 18
)

var (
	hwnd, hEdit, hBtn uintptr
	dpi               = 96
	fUI, fBold, fBig  uintptr
	icoSmall          uintptr
	emoji             [2]uintptr // 0 = accessible, 1 = blocked
	emojiSize         int32
	brushes           = map[uint32]uintptr{}
	active            = true
	pressed           int // 1 minimize, 2 close
	statusText        = "Ready."
	errText           string
	current           atomic.Pointer[Report]
	running           atomic.Bool
)

func rgb(r, g, b uint32) uint32 { return r | g<<8 | b<<16 }

var (
	cGrey   = rgb(192, 192, 192)
	cWhite  = rgb(255, 255, 255)
	cBlack  = rgb(0, 0, 0)
	cDark   = rgb(128, 128, 128)
	cLight  = rgb(223, 223, 223)
	cNavy   = rgb(0, 0, 128)
	cBlue   = rgb(0, 0, 255)
	cRed    = rgb(204, 0, 0)
	cOKText = rgb(0, 0, 204)
)

func S(n int) int32 { return int32((n*dpi + 48) / 96) }

func must(r uintptr, _ uintptr, _ error) uintptr { return r }

func u16(s string) *uint16 { p, _ := syscall.UTF16PtrFromString(s); return p }

// clean strips control characters from text that came off the network.
func clean(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s)
}

func fill(dc uintptr, l, t, r, b int32, c uint32) {
	br, ok := brushes[c]
	if !ok {
		br = must(pCreateBrush.Call(uintptr(c)))
		brushes[c] = br
	}
	rc := rect{l, t, r, b}
	pFillRect.Call(dc, uintptr(unsafe.Pointer(&rc)), br)
}

func th() int32 {
	if dpi >= 144 {
		return 2
	}
	return 1
}

func frame4(dc uintptr, l, t, r, b int32, oTL, oBR, iTL, iBR uint32) {
	w := th()
	fill(dc, l, t, r-w, t+w, oTL)
	fill(dc, l, t, l+w, b-w, oTL)
	fill(dc, l, b-w, r, b, oBR)
	fill(dc, r-w, t, r, b, oBR)
	fill(dc, l+w, t+w, r-2*w, t+2*w, iTL)
	fill(dc, l+w, t+w, l+2*w, b-2*w, iTL)
	fill(dc, l+w, b-2*w, r-w, b-w, iBR)
	fill(dc, r-2*w, t+w, r-w, b-w, iBR)
}

func raised(dc uintptr, l, t, r, b int32) { frame4(dc, l, t, r, b, cWhite, cBlack, cLight, cDark) }
func sunken(dc uintptr, l, t, r, b int32) { frame4(dc, l, t, r, b, cDark, cWhite, cBlack, cLight) }

func outline(dc uintptr, l, t, r, b int32, c uint32) {
	w := th()
	fill(dc, l, t, r, t+w, c)
	fill(dc, l, b-w, r, b, c)
	fill(dc, l, t, l+w, b, c)
	fill(dc, r-w, t, r, b, c)
}

func etched(dc uintptr, l, t, r, b int32) {
	w := th()
	outline(dc, l+w, t+w, r, b, cWhite)
	outline(dc, l, t, r-w, b-w, cDark)
}

func text(dc uintptr, s string, l, t, r, b int32, font uintptr, color uint32, flags uint32) {
	u := utf16.Encode([]rune(clean(s)))
	if len(u) == 0 {
		return
	}
	pSelectObject.Call(dc, font)
	pSetTextColor.Call(dc, uintptr(color))
	rc := rect{l, t, r, b}
	pDrawText.Call(dc, uintptr(unsafe.Pointer(&u[0])), uintptr(len(u)), uintptr(unsafe.Pointer(&rc)), uintptr(flags|dtNoPrefix))
}

func mkFont(h int32, weight int, face string) uintptr {
	return must(pCreateFont.Call(uintptr(-h), 0, 0, 0, uintptr(weight), 0, 0, 0, 1, 0, 0, 3, 0, uintptr(unsafe.Pointer(u16(face)))))
}

// makeEmoji box-filters the source PNG to size x size into a premultiplied 32-bit DIB.
func makeEmoji(data []byte, size int32) uintptr {
	img, err := png.Decode(bytes.NewReader(data))
	if err != nil {
		return 0
	}
	sw := img.Bounds().Dx()
	bi := bmih{Size: 40, W: size, H: -size, Planes: 1, BitCnt: 32}
	var bits unsafe.Pointer
	hb := must(pCreateDIB.Call(0, uintptr(unsafe.Pointer(&bi)), 0, uintptr(unsafe.Pointer(&bits)), 0, 0))
	if hb == 0 || bits == nil {
		return 0
	}
	buf := unsafe.Slice((*byte)(bits), int(size)*int(size)*4)
	n := int(size)
	for y := 0; y < n; y++ {
		y0, y1 := y*sw/n, (y+1)*sw/n
		if y1 <= y0 {
			y1 = y0 + 1
		}
		for x := 0; x < n; x++ {
			x0, x1 := x*sw/n, (x+1)*sw/n
			if x1 <= x0 {
				x1 = x0 + 1
			}
			var r, g, b, a, c uint64
			for yy := y0; yy < y1; yy++ {
				for xx := x0; xx < x1; xx++ {
					pr, pg, pb, pa := img.At(img.Bounds().Min.X+xx, img.Bounds().Min.Y+yy).RGBA()
					r, g, b, a, c = r+uint64(pr), g+uint64(pg), b+uint64(pb), a+uint64(pa), c+1
				}
			}
			o := (y*n + x) * 4
			buf[o], buf[o+1], buf[o+2], buf[o+3] = byte(b/c>>8), byte(g/c>>8), byte(r/c>>8), byte(a/c>>8)
		}
	}
	return hb
}

func drawEmoji(dc uintptr, hb uintptr, x, y int32) {
	if hb == 0 {
		return
	}
	mdc := must(pCreateCompatDC.Call(dc))
	old := must(pSelectObject.Call(mdc, hb))
	pAlphaBlend.Call(dc, uintptr(x), uintptr(y), uintptr(emojiSize), uintptr(emojiSize), mdc, 0, 0, uintptr(emojiSize), uintptr(emojiSize), 0x01FF0000)
	pSelectObject.Call(mdc, old)
	pDeleteDC.Call(mdc)
}

func fmtMs(v float64) string {
	switch {
	case v < 0:
		return "-"
	case v < 10:
		return fmt.Sprintf("%.1f ms", v)
	case v < 1000:
		return fmt.Sprintf("%.0f ms", v)
	}
	return fmt.Sprintf("%.2f s", v/1000)
}

func closeRect() rect {
	return rect{S(winW - frame - 2 - 16), S(frame + 2), S(winW - frame - 2), S(frame + 2 + 14)}
}
func minRect() rect {
	c := closeRect()
	return rect{c.L - S(18), c.T, c.R - S(18), c.B}
}
func inRect(r rect, x, y int32) bool { return x >= r.L && x < r.R && y >= r.T && y < r.B }

func paintAll(dc uintptr, W, H int32) {
	fill(dc, 0, 0, W, H, cGrey)
	raised(dc, 0, 0, W, H)
	pSetBkMode.Call(dc, 1)

	// title bar
	tc := cDark
	if active {
		tc = cNavy
	}
	fill(dc, S(frame), S(frame), W-S(frame), S(frame+titleH), tc)
	if icoSmall != 0 {
		pDrawIconEx.Call(dc, uintptr(S(frame+2)), uintptr(S(frame+1)), icoSmall, uintptr(S(16)), uintptr(S(16)), 0, 0, 3)
	}
	text(dc, "DNSCheck", S(frame+22), S(frame), W-S(80), S(frame+titleH), fBold, cWhite, dtVCenter|dtSingle)
	for i, r := range []rect{minRect(), closeRect()} {
		fill(dc, r.L, r.T, r.R, r.B, cGrey)
		off := int32(0)
		if pressed == i+1 {
			sunken(dc, r.L, r.T, r.R, r.B)
			off = th()
		} else {
			raised(dc, r.L, r.T, r.R, r.B)
		}
		cx, cy, u := (r.L+r.R)/2+off, (r.T+r.B)/2+off, S(1)
		if i == 0 {
			fill(dc, cx-3*u, cy+2*u, cx+3*u, cy+4*u, cBlack)
		} else {
			for k := int32(-3); k <= 3; k++ {
				fill(dc, cx+k*u-u, cy+k*u, cx+k*u+u, cy+k*u+u, cBlack)
				fill(dc, cx-k*u-u, cy+k*u, cx-k*u+u, cy+k*u+u, cBlack)
			}
		}
	}

	// input label
	text(dc, "Domain or URL:", S(16), S(33), S(300), S(50), fUI, cBlack, dtVCenter|dtSingle)

	var s Report
	if r := current.Load(); r != nil {
		s = r.snapshot()
	}

	// verdict panel
	pl, pt, pr, pb := S(16), S(88), S(winW-16), S(196)
	panel := cGrey
	switch {
	case s.Done && s.Verdict == VAccessible:
		panel = cBlue
	case s.Done && s.Verdict == VBlocked:
		panel = cRed
	case s.Host != "":
		panel = cDark
	}
	fill(dc, pl, pt, pr, pb, panel)
	sunken(dc, pl, pt, pr, pb)
	tx := pl + S(14)
	switch {
	case s.Done:
		if s.Verdict != VNone {
			idx := 1
			if s.Verdict == VAccessible {
				idx = 0
			}
			drawEmoji(dc, emoji[idx], pl+S(12), pt+(pb-pt-emojiSize)/2)
			tx = pl + S(12) + emojiSize + S(16)
		}
		text(dc, s.Headline, tx, pt+S(12), pr-S(10), pt+S(52), fBig, cWhite, dtVCenter|dtSingle)
		text(dc, s.Layer, tx, pt+S(56), pr-S(10), pb-S(8), fBold, cWhite, dtWordBreak)
	case s.Host != "":
		text(dc, "CHECKING...", tx, pt+S(12), pr-S(10), pt+S(52), fBig, cWhite, dtVCenter|dtSingle)
		text(dc, s.Host, tx, pt+S(56), pr-S(10), pb-S(8), fBold, cWhite, dtWordBreak)
	default:
		text(dc, "Type a domain name and press Check.", tx, pt, pr-S(10), pb, fBold, cBlack, dtVCenter|dtSingle)
	}

	// message box
	ml, mt, mr, mb := S(16), S(204), S(winW-16), S(250)
	etched(dc, ml, mt, mr, mb)
	msg, mc := s.Message, cBlack
	if s.Done {
		mc = cRed
		if s.Verdict == VAccessible {
			mc = cOKText
		} else if s.Verdict == VNone {
			mc = rgb(64, 64, 64)
		}
	} else if s.Host == "" && errText != "" {
		msg, mc = errText, cRed
	}
	text(dc, msg, ml+S(10), mt+S(4), mr-S(10), mb-S(4), fBold, mc, dtVCenter|dtWordBreak)

	// results table
	tl, tt, tr, tb := S(16), S(258), S(winW-16), S(480)
	fill(dc, tl, tt, tr, tb, cWhite)
	sunken(dc, tl, tt, tr, tb)
	cx := []int32{tl + S(2), tl + S(152), tr - S(72), tr - S(2)}
	hy := tt + S(2)
	for i, h := range []string{"Check", "Result", "Time"} {
		fill(dc, cx[i], hy, cx[i+1], hy+S(18), cGrey)
		raised(dc, cx[i], hy, cx[i+1], hy+S(18))
		text(dc, h, cx[i]+S(6), hy, cx[i+1]-S(4), hy+S(18), fUI, cBlack, dtVCenter|dtSingle)
	}
	y := hy + S(20)
	rows := s.Rows
	if s.Host == "" {
		rows = nil
	}
	for _, r := range rows {
		if y+S(22) > tb {
			break
		}
		col, mark := cDark, cWhite
		switch r.Status {
		case OK:
			col, mark = cOKText, cBlue
		case Fail:
			col, mark = cRed, cRed
		case Info:
			col, mark = rgb(64, 64, 64), cDark
		}
		outline(dc, cx[0]+S(6), y+S(6), cx[0]+S(16), y+S(16), cDark)
		fill(dc, cx[0]+S(7), y+S(7), cx[0]+S(15), y+S(15), mark)
		text(dc, r.Name, cx[0]+S(22), y, cx[1]-S(2), y+S(22), fUI, cBlack, dtVCenter|dtSingle|dtEllipsis)
		det := r.Detail
		if r.Status == Pending {
			det = "Waiting..."
		}
		text(dc, det, cx[1]+S(6), y, cx[2]-S(4), y+S(22), fUI, col, dtVCenter|dtSingle|dtEllipsis)
		text(dc, fmtMs(r.Ms), cx[2]+S(4), y, cx[3]-S(6), y+S(22), fUI, col, dtVCenter|dtSingle|dtRight)
		y += S(22)
	}

	// disclaimer
	dl, dt, dr, db := S(16), S(526), S(winW-16), S(574)
	etched(dc, dl, dt, dr, db)
	text(dc, "Diagnostic results may be affected by filters, caches, proxies and CDNs. Domain names are sent to Cloudflare and Google for public DNS checks, and to Globalping to test reachability from remote probes. Do not enter sensitive internal hostnames.",
		dl+S(8), dt+S(4), dr-S(8), db-S(4), fUI, cBlack, dtVCenter|dtWordBreak)

	// status bar
	sl, st, sr, sb := S(16), S(580), S(winW-16), S(600)
	sunken(dc, sl, st, sr-S(130), sb)
	text(dc, statusText, sl+S(6), st, sr-S(136), sb, fUI, cBlack, dtVCenter|dtSingle|dtEllipsis)
	sunken(dc, sr-S(126), st, sr, sb)
	text(dc, "DNSCheck 1.0", sr-S(126), st, sr, sb, fUI, cBlack, dtCenter|dtVCenter|dtSingle)
}

func onPaint(h uintptr) {
	var ps paintstruct
	hdc := must(pBeginPaint.Call(h, uintptr(unsafe.Pointer(&ps))))
	var rc rect
	pGetClientRect.Call(h, uintptr(unsafe.Pointer(&rc)))
	W, H := rc.R, rc.B
	mdc := must(pCreateCompatDC.Call(hdc))
	bmp := must(pCreateCompatBmp.Call(hdc, uintptr(W), uintptr(H)))
	old := must(pSelectObject.Call(mdc, bmp))
	paintAll(mdc, W, H)
	pBitBlt.Call(hdc, 0, 0, uintptr(W), uintptr(H), mdc, 0, 0, 0xCC0020)
	pSelectObject.Call(mdc, old)
	pDeleteObject.Call(bmp)
	pDeleteDC.Call(mdc)
	pEndPaint.Call(h, uintptr(unsafe.Pointer(&ps)))
}

func invalidate() { pInvalidate.Call(hwnd, 0, 0) }

func startCheck() {
	if running.Load() {
		return
	}
	buf := make([]uint16, 2100)
	n := must(pGetWindowText.Call(hEdit, uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf))))
	host, err := ParseHost(syscall.UTF16ToString(buf[:n]))
	if err != nil {
		current.Store(nil)
		errText, statusText = err.Error(), "Invalid input."
		invalidate()
		return
	}
	errText = ""
	r := newReport(host, func() { pPostMessage.Call(hwnd, wmApp, 0, 0) })
	current.Store(r)
	running.Store(true)
	pEnableWindow.Call(hBtn, 0)
	pSetWindowText.Call(hBtn, uintptr(unsafe.Pointer(u16("Checking..."))))
	statusText = "Checking " + host + "..."
	invalidate()
	go func() {
		defer func() {
			if recover() != nil {
				r.mu.Lock()
				r.Verdict, r.Headline, r.Layer, r.Message, r.Done = VBlocked, "ERROR", "Internal error", "The check could not be completed.", true
				r.mu.Unlock()
			}
			running.Store(false)
			r.ping()
		}()
		ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
		defer cancel()
		Run(ctx, host, r)
	}()
}

func wndProc(h, m, w, l uintptr) uintptr {
	switch uint32(m) {
	case wmEraseBkgnd:
		return 1
	case wmPaint:
		onPaint(h)
		return 0
	case wmNcHitTest:
		pt := point{int32(int16(l)), int32(int16(l >> 16))}
		pScreenToClient.Call(h, uintptr(unsafe.Pointer(&pt)))
		if pt.Y >= S(frame) && pt.Y < S(frame+titleH) && !inRect(minRect(), pt.X, pt.Y) && !inRect(closeRect(), pt.X, pt.Y) {
			return 2 // HTCAPTION
		}
		return 1
	case wmActivate:
		active = uint16(w) != 0
		invalidate()
	case wmLButtonDown:
		x, y := int32(int16(l)), int32(int16(l>>16))
		switch {
		case inRect(minRect(), x, y):
			pressed = 1
		case inRect(closeRect(), x, y):
			pressed = 2
		}
		if pressed != 0 {
			pSetCapture.Call(h)
			invalidate()
		}
		return 0
	case wmLButtonUp:
		x, y := int32(int16(l)), int32(int16(l>>16))
		p := pressed
		pressed = 0
		pReleaseCapture.Call()
		invalidate()
		if p == 1 && inRect(minRect(), x, y) {
			pShowWindow.Call(h, 6)
		} else if p == 2 && inRect(closeRect(), x, y) {
			pPostMessage.Call(h, wmClose, 0, 0)
		}
		return 0
	case wmCommand:
		switch uint16(w) {
		case idCheck:
			startCheck()
		}
		return 0
	case wmApp:
		if s := current.Load(); s != nil {
			if !running.Load() {
				pEnableWindow.Call(hBtn, 1)
				pSetWindowText.Call(hBtn, uintptr(unsafe.Pointer(u16("Check"))))
				snap := s.snapshot()
				if snap.Done {
					statusText = fmt.Sprintf("Finished %s in %s.", snap.Host, fmtMs(snap.TotalMs))
				}
			}
		}
		invalidate()
		return 0
	case wmDestroy:
		pPostQuit.Call(0)
		return 0
	}
	return must(pDefWindowProc.Call(h, uintptr(m), w, l))
}

func init() { runtime.LockOSThread() }

func main() {
	pSetDefaultDllDirs.Call(0x800) // LOAD_LIBRARY_SEARCH_SYSTEM32: no DLL planting from the app folder
	inst := must(pGetModuleHandle.Call(0))

	dc := must(pGetDC.Call(0))
	if v := must(pGetDeviceCaps.Call(dc, 88)); v >= 96 {
		dpi = int(v)
	}
	pReleaseDC.Call(0, dc)

	fUI = mkFont(S(11), 400, "Microsoft Sans Serif")
	fBold = mkFont(S(11), 700, "Microsoft Sans Serif")
	fBig = mkFont(S(26), 700, "Microsoft Sans Serif")
	emojiSize = S(88)
	emoji[0], emoji[1] = makeEmoji(allowPNG, emojiSize), makeEmoji(blockPNG, emojiSize)

	icoBig := must(pLoadImage.Call(inst, 1, 1, uintptr(must(pGetSysMetrics.Call(11))), uintptr(must(pGetSysMetrics.Call(12))), 0))
	icoSmall = must(pLoadImage.Call(inst, 1, 1, uintptr(S(16)), uintptr(S(16)), 0))
	icoTask := must(pLoadImage.Call(inst, 1, 1, uintptr(must(pGetSysMetrics.Call(49))), uintptr(must(pGetSysMetrics.Call(50))), 0))

	cls := wndclassex{
		WndProc: syscall.NewCallback(wndProc), Instance: inst, Icon: icoBig, IconSm: icoTask,
		Curs:      must(pLoadCursor.Call(0, 32512)),
		ClassName: u16("DNSCheckWnd"),
	}
	cls.Size = uint32(unsafe.Sizeof(cls))
	if must(pRegisterClass.Call(uintptr(unsafe.Pointer(&cls)))) == 0 {
		return
	}

	W, H := S(winW), S(winH)
	sx, sy := must(pGetSysMetrics.Call(0)), must(pGetSysMetrics.Call(1))
	x, y := (int32(sx)-W)/2, (int32(sy)-H)/2
	if x < 0 {
		x = 0
	}
	if y < 0 {
		y = 0
	}
	hwnd = must(pCreateWindowEx.Call(wsExAppWindow, uintptr(unsafe.Pointer(cls.ClassName)), uintptr(unsafe.Pointer(u16("DNSCheck"))),
		wsPopup|wsMinBox|wsSysMenu|wsClipKids, uintptr(x), uintptr(y), uintptr(W), uintptr(H), 0, 0, inst, 0))
	if hwnd == 0 {
		return
	}
	hEdit = must(pCreateWindowEx.Call(wsExClientEdge, uintptr(unsafe.Pointer(u16("EDIT"))), 0,
		wsChild|wsVisible|wsTabStop|esAutoHScroll, uintptr(S(16)), uintptr(S(52)), uintptr(S(480)), uintptr(S(24)), hwnd, 0, inst, 0))
	hBtn = must(pCreateWindowEx.Call(0, uintptr(unsafe.Pointer(u16("BUTTON"))), uintptr(unsafe.Pointer(u16("Check"))),
		wsChild|wsVisible|wsTabStop|bsDefPush, uintptr(S(504)), uintptr(S(51)), uintptr(S(120)), uintptr(S(26)), hwnd, idCheck, inst, 0))
	for _, c := range []uintptr{hEdit, hBtn} {
		pSendMessage.Call(c, wmSetFont, fUI, 1)
	}
	pSendMessage.Call(hEdit, emLimitText, 2048, 0)
	pShowWindow.Call(hwnd, 5)
	pSetFocus.Call(hEdit)

	var m winmsg
	for {
		r := must(pGetMessage.Call(uintptr(unsafe.Pointer(&m)), 0, 0, 0))
		if int32(r) <= 0 {
			break
		}
		if m.Message == wmKeyDown {
			ctrl := must(pGetKeyState.Call(vkCtrl))&0x8000 != 0
			switch {
			case m.WParam == vkReturn && (m.Hwnd == hEdit || m.Hwnd == hBtn):
				startCheck()
				continue
			case m.WParam == vkTab && (m.Hwnd == hEdit || m.Hwnd == hBtn):
				if m.Hwnd == hEdit {
					pSetFocus.Call(hBtn)
				} else {
					pSetFocus.Call(hEdit)
				}
				continue
			case ctrl && m.WParam == 'A' && m.Hwnd == hEdit:
				pSendMessage.Call(hEdit, emSetSel, 0, ^uintptr(0))
				continue
			}
		}
		pTranslateMsg.Call(uintptr(unsafe.Pointer(&m)))
		pDispatchMsg.Call(uintptr(unsafe.Pointer(&m)))
	}
}

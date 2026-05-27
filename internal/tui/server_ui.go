package tui

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/RGPtv/gotunnel/internal/ipc"
)

func RunServerUI(ipcPort int) error {
	ipcClient := ipc.NewClient(ipcPort)
	quit := make(chan struct{})

	go func() {
		readInput(
			func() { // Ctrl+C
				ipcClient.Shutdown()
				close(quit)
			},
			func() { // Ctrl+D
				close(quit)
			},
		)
	}()

	altScreen()
	hideCursor()
	defer func() {
		showCursor()
		mainScreen()
	}()

	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	renderServerUI(ipcClient)

	for {
		select {
		case <-quit:
			return nil
		case <-ticker.C:
			renderServerUI(ipcClient)
		}
	}
}

func renderServerUI(ipcClient *ipc.Client) {
	state, err := ipcClient.GetServerState()
	w, h := termSize()
	if w < 60 {
		w = 60
	}

	var b strings.Builder
	b.WriteString(esc + "H") // cursor home

	// ── connecting / error states ─────────────────────────────────────────────
	if err != nil {
		renderSplash(&b, w, h, red+"  ✗  Disconnected from server"+reset, "")
		b.WriteString(esc + "J")
		fmt.Fprint(os.Stdout, b.String())
		return
	}
	if state.Token == "" {
		renderSplash(&b, w, h, yellow+"  ◌  Connecting to GoTunnel server…"+reset, "")
		b.WriteString(esc + "J")
		fmt.Fprint(os.Stdout, b.String())
		return
	}

	uptime := fmtDuration(time.Duration(state.Uptime) * time.Second)

	// ── header ────────────────────────────────────────────────────────────────
	renderHeader(&b, w, "GoTunnel Server", uptime, "SERVER")

	// ── stats strip ──────────────────────────────────────────────────────────
	statsLine := fmt.Sprintf(
		"  %s ACTIVE %s%d%s   %s REQUESTS %s%d%s   %s UPTIME %s%s%s",
		dim+"┃"+reset, green+bold, state.ActiveConns, reset,
		dim+"┃"+reset, cyan+bold, state.TotalReqs, reset,
		dim+"┃"+reset, blue+bold, uptime, reset,
	)
	writeLine(&b, statsLine, w)
	writeLine(&b, dim+strings.Repeat("─", w)+reset, w)

	// ── config panel ──────────────────────────────────────────────────────────
	inspectUrl := "—"
	if state.InspectAddr != "" {
		inspectUrl = "http://" + state.InspectAddr
	}
	col := w / 2

	writeLine(&b, " "+dim+"Configuration"+reset, w)
	writeLine(&b, dim+strings.Repeat("·", w)+reset, w)

	row1 := cfgCell("  HTTP Proxy", state.HTTPAddr, col) + cfgCell("  Tunnel Port", state.TunAddr, w-col)
	row2 := cfgCell("  HTTPS     ", orDash(state.HTTPSAddr), col) + cfgCell("  Dashboard ", inspectUrl, w-col)
	row3 := cfgCell("  Token     ", maskSecret(state.Token), col) + cfgCell("  Login     ", state.DashUser+"/"+maskSecret(state.DashPass), w-col)

	writeLine(&b, row1, w)
	writeLine(&b, row2, w)
	writeLine(&b, row3, w)
	writeLine(&b, dim+strings.Repeat("─", w)+reset, w)

	// ── tunnels table ─────────────────────────────────────────────────────────
	writeLine(&b, " "+dim+"Active Tunnels"+reset, w)

	headerH := 11 // header+stats+config lines used
	logLines := 9 // reserved for log pane
	separators := 4
	tunnelH := h - headerH - logLines - separators
	if tunnelH < 2 {
		tunnelH = 2
	}

	epW := 26
	typeW := 6
	conW := 6
	ipW := 18
	urlW := w - epW - typeW - conW - ipW - 5

	th := dim +
		"  " + pad("ENDPOINT", epW) +
		pad("TYPE", typeW) +
		rpad("CONNS", conW) + "  " +
		pad("CLIENT IP", ipW) +
		pad("PROXY URL", urlW) +
		reset
	writeLine(&b, th, w)
	writeLine(&b, dim+strings.Repeat("·", w)+reset, w)

	shown := state.Tunnels
	if len(shown) > tunnelH {
		shown = shown[:tunnelH]
	}
	for _, tun := range shown {
		typeColor := "\x1b[38;5;39m" // bright blue for http
		badge := " http"
		if tun.Type == "tcp" {
			typeColor = "\x1b[38;5;213m" // pink/magenta for tcp
			badge = "  tcp"
		}
		line := "  " +
			bold + pad(tun.Endpoint, epW) + reset +
			typeColor + pad(badge, typeW) + reset +
			"\x1b[38;5;82m" + rpad(fmt.Sprintf("%d", tun.Connections), conW) + reset + "  " +
			dim + pad(orDash(tun.ClientIP), ipW) + reset + " " +
			"\x1b[38;5;39m" + pad(orDash(tun.ProxyURL), urlW) + reset
		writeLine(&b, line, w)
	}
	if len(shown) == 0 {
		noTunnel := dim + "  No active tunnels" + reset
		writeLine(&b, noTunnel, w)
	}
	for i := len(shown); i < tunnelH; i++ {
		writeLine(&b, "", w)
	}

	writeLine(&b, dim+strings.Repeat("─", w)+reset, w)

	// ── event log ─────────────────────────────────────────────────────────────
	writeLine(&b, " "+dim+"Event Log"+reset, w)
	writeLine(&b, dim+strings.Repeat("·", w)+reset, w)

	last := state.Logs
	maxLogs := logLines - 3
	if maxLogs < 1 {
		maxLogs = 1
	}
	if len(last) > maxLogs {
		last = last[len(last)-maxLogs:]
	}
	for _, e := range last {
		col2, sym, lvlLabel := logStyleFull(e.Level)
		ts := e.Time.Format("15:04:05")
		msg := e.Message
		if len(msg)+20 > w {
			msg = msg[:w-20] + "…"
		}
		line := fmt.Sprintf("  %s%s%s  %s%s%s  %s%s",
			dim, ts, reset,
			col2, sym+" "+lvlLabel, reset,
			reset, msg)
		writeLine(&b, line, w)
	}
	for i := len(last); i < maxLogs; i++ {
		writeLine(&b, "", w)
	}

	// ── footer / keybind bar ──────────────────────────────────────────────────
	renderFooter(&b, w, "ctrl+d  detach", "ctrl+c  stop server")

	b.WriteString(esc + "J")
	fmt.Fprint(os.Stdout, b.String())
}

// ── Shared helpers ────────────────────────────────────────────────────────────

func renderHeader(b *strings.Builder, w int, title, subtitle, badge string) {
	// Full-width gradient-style header using 256-color bg
	bg := "\x1b[48;5;24m" // deep teal
	fg := "\x1b[38;5;231m"
	accent := "\x1b[38;5;123m"

	left := fmt.Sprintf("%s%s %s %s %s", bg, fg, bold+"◈"+reset+bg+fg, bold+title+reset+bg+fg, reset)
	right := fmt.Sprintf("%s%s %s %s", bg, accent+dim, subtitle, reset)
	badgeStr := fmt.Sprintf("%s %s %s", "\x1b[48;5;39m"+"\x1b[38;5;17m", bold+badge+reset, "")

	leftVis := len("◈ " + title + "  ")
	rightVis := len(subtitle) + 1
	badgeVis := len(badge) + 2
	padding := w - leftVis - rightVis - badgeVis
	if padding < 0 {
		padding = 0
	}

	line := left + strings.Repeat(" ", padding) + right + badgeStr
	b.WriteString(line + "\n")
}

func renderSplash(b *strings.Builder, w, h int, msg, sub string) {
	for i := 0; i < h/2-1; i++ {
		b.WriteString("\n")
	}
	b.WriteString(strings.Repeat(" ", (w-len(msg))/2) + msg + "\n")
	if sub != "" {
		b.WriteString(strings.Repeat(" ", (w-len(sub))/2) + dim + sub + reset + "\n")
	}
}

func renderFooter(b *strings.Builder, w int, left, right string) {
	bg := "\x1b[48;5;236m"
	fg := "\x1b[38;5;245m"
	accent := "\x1b[38;5;39m"

	l := fmt.Sprintf("%s%s  %s %s", bg, fg, accent+"⌨"+reset+bg+fg, left)
	r := fmt.Sprintf("%s %s  ", accent+"✕"+reset+bg+fg, right)
	lv := len(left) + 4
	rv := len(right) + 4
	pad := w - lv - rv
	if pad < 0 {
		pad = 0
	}
	b.WriteString(l + strings.Repeat(" ", pad) + r + reset + "\n")
}

func cfgCell(label, value string, width int) string {
	if value == "" || value == "/" {
		value = "—"
	}
	lbl := dim + label + reset + " "
	val := "\x1b[38;5;123m" + value + reset
	visLen := len(label) + 1 + len(value)
	padLen := width - visLen
	if padLen < 1 {
		padLen = 1
	}
	return lbl + val + strings.Repeat(" ", padLen)
}

func logStyleFull(level int) (color, sym, label string) {
	switch level {
	case 0:
		return "\x1b[38;5;39m", "·", "INFO "
	case 1:
		return "\x1b[38;5;214m", "!", "WARN "
	case 2:
		return "\x1b[38;5;196m", "✗", "ERROR"
	case 3:
		return "\x1b[38;5;82m", "✓", "OK   "
	default:
		return dim, "·", "INFO "
	}
}

func logStyle(level int) (color, sym string) {
	c, s, _ := logStyleFull(level)
	return c, s
}

func fmtDuration(d time.Duration) string {
	d = d.Round(time.Second)
	h := int(d.Hours())
	m := int(d.Minutes()) % 60
	s := int(d.Seconds()) % 60
	if h > 0 {
		return fmt.Sprintf("%dh%02dm%02ds", h, m, s)
	}
	return fmt.Sprintf("%dm%02ds", m, s)
}

func maskSecret(s string) string {
	if s == "" {
		return "—"
	}
	if len(s) <= 8 {
		return "••••••••"
	}
	return s[:4] + "••••••" + s[len(s)-2:]
}

func orDash(s string) string {
	if s == "" {
		return "—"
	}
	return s
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func infoCell(label, value string, width int) string {
	return cfgCell(label, value, width)
}

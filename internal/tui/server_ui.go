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

	// Start reading input in a separate goroutine
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

	// Initial render
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
	
	var b strings.Builder
	b.WriteString(esc + "H") // cursor home

	if err != nil {
		b.WriteString(fmt.Sprintf("\n%s  Disconnected from server: %v%s\n", red, err, reset))
		b.WriteString(esc + "J")
		fmt.Fprint(os.Stdout, b.String())
		return
	}
	if state.Token == "" {
		b.WriteString("\n  Connecting to gotunnel server daemon...\n")
		b.WriteString(esc + "J")
		fmt.Fprint(os.Stdout, b.String())
		return
	}

	// ── header bar ───────────────────────────────────────────────────────────
	title := "  GoTunnel Server "
	uptime := fmt.Sprintf("  uptime %s  ", fmtDuration(time.Duration(state.Uptime)*time.Second))
	header := bold + bgCyan + " " + title + reset
	header += strings.Repeat(" ", max(0, w-len(title)-len(uptime)-2))
	header += dim + uptime + reset
	writeLine(&b, header, w)
	b.WriteString(dim + hline(w, "─") + reset + "\n")

	// ── info pane ─────────────────────────────────────────────────────────────
	col := w / 2

	inspectUrl := "—"
	if state.InspectAddr != "" {
		inspectUrl = "http://" + state.InspectAddr
	}

	row1 := infoCell("HTTP  ", state.HTTPAddr, col) + infoCell("Tunnel", state.TunAddr, w-col)
	row2 := infoCell("HTTPS ", state.HTTPSAddr, col) + infoCell("Dashb.", inspectUrl, w-col)
	row3 := infoCell("Token ", maskSecret(state.Token), col) + infoCell("Login ", state.DashUser+"/"+maskSecret(state.DashPass), w-col)
	row4 := infoCell("Conns ", fmt.Sprintf("%d", state.ActiveConns), col) + infoCell("Reqs  ", fmt.Sprintf("%d", state.TotalReqs), w-col)

	writeLine(&b, row1, w)
	writeLine(&b, row2, w)
	writeLine(&b, row3, w)
	writeLine(&b, row4, w)

	b.WriteString(dim + hline(w, "─") + reset + "\n")

	// ── tunnels pane ─────────────────────────────────────────────────────────
	tunnelHeaderH := 8
	logLines := 10
	separators := 3

	tunnelH := h - tunnelHeaderH - logLines - separators
	if tunnelH < 3 {
		tunnelH = 3
	}

	th := bold + dim +
		" " + pad("ENDPOINT", 28) +
		pad("TYPE", 6) +
		rpad("CONNS", 7) + "  " +
		pad("CLIENT IP", 22) +
		pad("PROXY URL", w-28-6-7-2-22-1) +
		reset
	writeLine(&b, th, w)
	b.WriteString(dim + hline(w, "·") + reset + "\n")

	shown := state.Tunnels
	if len(shown) > tunnelH-2 {
		shown = shown[:tunnelH-2]
	}
	for _, tun := range shown {
		typeColor := cyan
		if tun.Type == "tcp" {
			typeColor = magenta
		}
		line := " " +
			bold + pad(tun.Endpoint, 28) + reset +
			typeColor + pad(tun.Type, 6) + reset +
			green + rpad(fmt.Sprintf("%d", tun.Connections), 7) + reset + "  " +
			dim + pad(orDash(tun.ClientIP), 22) + reset +
			dim + pad(orDash(tun.ProxyURL), w-28-6-7-2-22-1) + reset
		writeLine(&b, line, w)
	}
	for i := len(shown); i < tunnelH-2; i++ {
		writeLine(&b, "", w)
	}

	b.WriteString(dim + hline(w, "─") + reset + "\n")

	// ── log pane ─────────────────────────────────────────────────────────────
	writeLine(&b, dim+" event log"+reset, w)

	last := state.Logs
	if len(last) > logLines-1 {
		last = last[len(last)-(logLines-1):]
	}
	for _, e := range last {
		col, sym := logStyle(e.Level)
		ts := e.Time.Format("15:04:05")
		line := fmt.Sprintf(" %s%s%s %s%s%s %s",
			dim, ts, reset,
			col, sym, reset,
			e.Message)
		writeLine(&b, line, w)
	}
	for i := len(last); i < logLines-1; i++ {
		writeLine(&b, "", w)
	}

	// ── help bar ──────────────────────────────────────────────────────────────
	writeLine(&b, dim+"  ctrl+d: detach • ctrl+c: stop server"+reset, w)

	b.WriteString(esc + "J") // clear to end
	fmt.Fprint(os.Stdout, b.String())
}

// Helpers

func infoCell(label, value string, width int) string {
	if value == "" {
		value = "—"
	}
	lbl := dim + " " + label + " " + reset
	val := cyan + value + reset
	visLen := 1 + len(label) + 1 + len(value)
	padLen := width - visLen - 1
	if padLen < 0 { padLen = 0 }
	return lbl + val + strings.Repeat(" ", padLen)
}

func logStyle(level int) (color, sym string) {
	switch level {
	case 0: return cyan, "·"
	case 1: return yellow, "!"
	case 2: return red, "✗"
	case 3: return green, "✓"
	default: return dim, "·"
	}
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
	if len(s) <= 8 {
		return "••••••••"
	}
	return s[:6] + "••••••"
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

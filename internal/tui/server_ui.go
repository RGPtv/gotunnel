package tui

import (
	"fmt"
	"strings"
	"time"

	"github.com/RGPtv/gotunnel/internal/ipc"
)

func RunServerUI(ipcPort int) error {
	ipcClient := ipc.NewClient(ipcPort)
	quit := make(chan struct{})

	go func() {
		readInput(
			func() { ipcClient.Shutdown(); close(quit) }, // Ctrl+C
			func() { close(quit) },                       // Ctrl+D
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

	drawServerFrame(ipcClient)
	for {
		select {
		case <-quit:
			return nil
		case <-ticker.C:
			drawServerFrame(ipcClient)
		}
	}
}

func drawServerFrame(ipcClient *ipc.Client) {
	w, h := termSize()
	if w < 60 {
		w = 60
	}

	var b strings.Builder

	// Move cursor to top-left without clearing — avoids the full-screen flash
	b.WriteString("\x1b[H")

	state, err := ipcClient.GetServerState()
	if err != nil {
		renderSplash(&b, w, h, red+"  ✗  Disconnected from server"+reset)
		b.WriteString("\x1b[J") // clear rest of screen
		flush(&b)
		return
	}
	if state.Token == "" {
		renderSplash(&b, w, h, yellow+"  ◌  Connecting to GoTunnel server…"+reset)
		b.WriteString("\x1b[J")
		flush(&b)
		return
	}

	uptime := serverUptime(state.Uptime)

	// ── 1. Header ─────────────────────────────────────────────────────────────
	renderHeader(&b, w, "GoTunnel Server", uptime, "SERVER")

	// ── 2. Stats strip ────────────────────────────────────────────────────────
	statsLine :=
		"  " +
			statsBadge("CONNS", fmt.Sprintf("%d", state.ActiveConns), lgreen) +
			statsBadge("REQUESTS", fmt.Sprintf("%d", state.TotalReqs), lblue) +
			statsBadge("UPTIME", uptime, lteal)
	writeLine(&b, statsLine, w)
	writeLine(&b, dim+hline(w, "─")+reset, w)

	// ── 3. Config panel ───────────────────────────────────────────────────────
	inspectUrl := "—"
	if state.InspectAddr != "" {
		if strings.HasPrefix(state.InspectAddr, ":") {
			inspectUrl = "http://localhost" + state.InspectAddr
		} else {
			inspectUrl = "http://" + state.InspectAddr
		}
	}

	writeLine(&b, " "+dim+"Configuration"+reset, w)
	writeLine(&b, dim+hline(w, "·")+reset, w)

	col := w / 2
	writeLine(&b, cfgCell("  HTTP Proxy ", state.HTTPAddr, col)+cfgCell("  Tunnel Port", state.TunAddr, w-col), w)
	writeLine(&b, cfgCell("  HTTPS      ", orDash(state.HTTPSAddr), col)+cfgCell("  Dashboard  ", inspectUrl, w-col), w)
	writeLine(&b, cfgCell("  Token      ", maskSecret(state.Token), col)+cfgCell("  Login      ", state.DashUser+"/"+maskSecret(state.DashPass), w-col), w)
	writeLine(&b, dim+hline(w, "─")+reset, w)

	// ── 4. Tunnels table ──────────────────────────────────────────────────────
	writeLine(&b, " "+dim+"Active Tunnels"+reset, w)

	// Calculate remaining height for tunnels + log sections
	// Lines used so far: 1(hdr)+1(stats)+1(sep)+1(cfg-label)+1(cfg-dot)+3(cfg-rows)+1(sep)+1(tun-label) = 10
	const (
		usedLines = 10
		footerH   = 1
	)
	
	avail := h - usedLines - footerH - 5 // 3 for tunnel header/sep, 2 for log header
	if avail < 2 {
		avail = 2
	}
	
	maxLogs := avail / 3
	if maxLogs < 3 {
		maxLogs = 3
	} else if maxLogs > 15 {
		maxLogs = 15
	}
	
	tunnelH := avail - maxLogs
	if tunnelH < 1 {
		tunnelH = 1
	}

	epW := 26
	typeW := 6
	conW := 7
	ipW := 18
	urlW := w - epW - typeW - conW - ipW - 4
	if urlW < 8 {
		urlW = 8
	}

	th := dim + "  " +
		pad("ENDPOINT", epW) +
		pad("TYPE", typeW) +
		rpad("CONNS", conW) + " " +
		pad("CLIENT IP", ipW) +
		pad("PROXY URL", urlW) + reset
	writeLine(&b, th, w)
	writeLine(&b, dim+hline(w, "·")+reset, w)

	shown := state.Tunnels
	var overflow int
	if len(shown) > tunnelH {
		overflow = len(shown) - (tunnelH - 1)
		shown = shown[:tunnelH-1]
	}
	for _, tun := range shown {
		typeColor := lblue
		badge := "http"
		if tun.Type == "tcp" {
			typeColor = lpink
			badge = "tcp "
		}
		line := "  " +
			bold + pad(tun.Endpoint, epW) + reset +
			typeColor + pad(badge, typeW) + reset +
			lgreen + rpad(fmt.Sprintf("%d", tun.Connections), conW) + reset + " " +
			dim + pad(orDash(tun.ClientIP), ipW) + reset +
			lblue + pad(orDash(tun.ProxyURL), urlW) + reset
		writeLine(&b, line, w)
	}
	if len(shown) == 0 {
		writeLine(&b, dim+"  No active tunnels — waiting for clients…"+reset, w)
	}
	if overflow > 0 {
		writeLine(&b, dim+fmt.Sprintf("  ... and %d more active tunnels", overflow)+reset, w)
	} else {
		for i := len(shown); i < tunnelH; i++ {
			writeLine(&b, "", w)
		}
	}
	writeLine(&b, dim+hline(w, "─")+reset, w)

	// ── 5. Event log ──────────────────────────────────────────────────────────
	writeLine(&b, " "+dim+"Event Log"+reset, w)
	writeLine(&b, dim+hline(w, "·")+reset, w)

	last := state.Logs
	if len(last) > maxLogs {
		last = last[len(last)-maxLogs:]
	}
	for _, e := range last {
		col2, sym, lvl := logStyleFull(e.Level)
		ts := e.Time.Format("15:04:05")
		msg := e.Message
		maxMsg := w - 22
		if maxMsg > 0 && len([]rune(msg)) > maxMsg {
			msg = string([]rune(msg)[:maxMsg-1]) + "…"
		}
		writeLine(&b, fmt.Sprintf("  %s%s%s  %s%s %s%s  %s",
			dim, ts, reset,
			col2, sym, lvl, reset,
			msg), w)
	}
	for i := len(last); i < maxLogs; i++ {
		writeLine(&b, "", w)
	}

	// ── 6. Footer ─────────────────────────────────────────────────────────────
	renderFooter(&b, w, "ctrl+d  detach", "ctrl+c  stop server")

	// Clear any leftover lines from a previous taller frame
	b.WriteString("\x1b[J")

	flush(&b)
}

func serverUptime(seconds int64) string {
	d := time.Duration(seconds) * time.Second
	h := int(d.Hours())
	m := int(d.Minutes()) % 60
	s := int(d.Seconds()) % 60
	if h > 0 {
		return fmt.Sprintf("%dh%02dm%02ds", h, m, s)
	}
	return fmt.Sprintf("%dm%02ds", m, s)
}

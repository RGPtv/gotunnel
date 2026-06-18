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
	// Leave the rightmost column and bottom row empty to prevent scroll/wrap.
	w--
	h--
	if w < 60 {
		w = 60
	}
	if h < 10 {
		h = 10
	}

	var b strings.Builder

	// Home cursor without clearing — avoids full-screen flash.
	// The synchronized-output sequences in flush() make this truly atomic.
	b.WriteString("\x1b[H")

	state, err := ipcClient.GetServerState()
	if err != nil {
		renderSplash(&b, w, h, red+"  ✗  Disconnected from server"+reset)
		b.WriteString("\x1b[J")
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
	renderHeader(&b, w, "GoTunnel Server", uptime, "SERVER") // 1 line

	// ── 2. Stats strip ────────────────────────────────────────────────────────
	statsLine := statsBadge("CONNS", fmt.Sprintf("%d", state.ActiveConns), lgreen) +
		statsBadge("REQUESTS", fmt.Sprintf("%d", state.TotalReqs), lblue) +
		statsBadge("UPTIME", uptime, lteal)
	statsVis := len([]rune(strings.TrimRight(stripANSI(statsLine), " ")))
	padLen := (w - statsVis) / 2
	if padLen < 0 {
		padLen = 0
	}
	writeLine(&b, strings.Repeat(" ", padLen)+statsLine, w) // 1 line
	writeLine(&b, "", w)                                     // 1 line (spacer)

	// ── 3. Config panel ───────────────────────────────────────────────────────
	inspectUrl := "—"
	if state.InspectAddr != "" {
		if strings.HasPrefix(state.InspectAddr, ":") {
			inspectUrl = "http://localhost" + state.InspectAddr
		} else {
			inspectUrl = "http://" + state.InspectAddr
		}
	}

	col := (w - 8) / 2

	panelTop(&b, "Configuration", w)                                                                                                  // 1 line
	panelRow(&b, cfgCell(" HTTP Proxy ", state.HTTPAddr, col)+cfgCell(" Tunnel Port", state.TunAddr, w-8-col), w)                     // 1 line
	panelRow(&b, cfgCell(" HTTPS      ", orDash(state.HTTPSAddr), col)+cfgCell(" Dashboard  ", inspectUrl, w-8-col), w)               // 1 line
	panelRow(&b, cfgCell(" Token      ", maskSecret(state.Token), col)+cfgCell(" Login      ", state.DashUser+"/"+maskSecret(state.DashPass), w-8-col), w) // 1 line
	panelBottom(&b, w)                                                                                                                 // 1 line
	writeLine(&b, "", w)                                                                                                               // 1 line (spacer)

	// ── 4. Tunnels table ──────────────────────────────────────────────────────
	//
	// Fixed lines drawn above this point:
	//   header(1) + stats(1) + spacer(1) + cfgTop(1) + cfgRows(3) + cfgBot(1) + spacer(1) = 9
	//
	// Fixed lines inside the tunnels+log section (not counted in usedLines):
	//   tunTop(1) + tunHdr(1) + tunSep(1) + tunBot(1)
	//   + logSpacer(1) + logTop(1) + logBot(1) = 7
	//
	// Fixed lines after variable content:
	//   footer(1) = 1
	//
	// So the budget for variable rows = h - 9 - 7 - 1 = h - 17
	const (
		fixedAbove  = 9  // lines drawn before panelTop("Active Tunnels")
		fixedInside = 7  // fixed box-chrome lines inside the two panels
		fixedBelow  = 1  // footer
	)

	panelTop(&b, "Active Tunnels", w) // 1 line (counted in fixedInside)

	varBudget := h - fixedAbove - fixedInside - fixedBelow
	if varBudget < 4 {
		varBudget = 4
	}

	// Give logs 1/3 of the variable budget (min 3, max 15).
	maxLogs := varBudget / 3
	if maxLogs < 3 {
		maxLogs = 3
	} else if maxLogs > 15 {
		maxLogs = 15
	}
	tunnelH := varBudget - maxLogs
	if tunnelH < 1 {
		tunnelH = 1
	}

	// Dynamic table layout for active tunnels.
	epW := 22
	typeW := 6
	conW := 5
	ipW := 21
	maxUrlW := 36

	innerW := w - 8
	if innerW < 0 {
		innerW = 0
	}

	urlW := innerW - (epW + typeW + conW + ipW + 8) // 8 is min gaps (4 * 2)
	if urlW > maxUrlW {
		urlW = maxUrlW
	} else if urlW < 8 {
		urlW = 8
	}

	totalCols := epW + typeW + conW + ipW + urlW
	availableExtra := innerW - totalCols

	gapSize := availableExtra / 6
	if gapSize < 2 {
		gapSize = 2
	}
	if gapSize > 6 {
		gapSize = 6
	}

	usedByGaps := gapSize * 4
	leftPad := 0
	if availableExtra > usedByGaps {
		leftPad = (availableExtra - usedByGaps) / 2
	}

	sep := strings.Repeat(" ", gapSize)
	margin := strings.Repeat(" ", leftPad)

	th := margin + dim +
		pad("ENDPOINT", epW) + sep +
		pad("TYPE", typeW) + sep +
		rpad("CONNS", conW) + sep +
		pad("CLIENT IP", ipW) + sep +
		pad("PROXY URL", urlW) + reset
	panelRow(&b, th, w) // 1 line (counted in fixedInside)
	panelSep(&b, w)     // 1 line (counted in fixedInside)

	shown := state.Tunnels
	var overflow int
	if len(shown) > tunnelH {
		overflow = len(shown) - (tunnelH - 1)
		shown = shown[:tunnelH-1]
	}
	for _, tun := range shown {
		typeColor := bgLblue + "\x1b[38;5;17m" + bold
		badge := " HTTP "
		if tun.Type == "tcp" {
			typeColor = bgCyan + "\x1b[38;5;16m" + bold
			badge = " TCP  "
		}
		line := margin + bold + pad(tun.Endpoint, epW) + reset + sep +
			typeColor + pad(badge, typeW) + reset + sep +
			lgreen + rpad(fmt.Sprintf("%d", tun.Connections), conW) + reset + sep +
			dim + pad(orDash(tun.ClientIP), ipW) + reset + sep +
			lblue + pad(orDash(tun.ProxyURL), urlW) + reset
		panelRow(&b, line, w)
	}
	// padStart tracks how many variable rows have already been written,
	// so the empty-message (if any) is counted as one of the tunnelH rows
	// rather than being added on top of them.
	padStart := len(shown)
	if len(shown) == 0 {
		panelRow(&b, dim+"No active tunnels — waiting for clients…"+reset, w)
		padStart = 1
	}
	if overflow > 0 {
		panelRow(&b, dim+fmt.Sprintf("… and %d more active tunnels", overflow)+reset, w)
	} else {
		// Pad remaining rows so the box bottom is always at a fixed position.
		for i := padStart; i < tunnelH; i++ {
			panelRow(&b, "", w)
		}
	}
	panelBottom(&b, w) // 1 line (counted in fixedInside)

	// ── 5. Event log ──────────────────────────────────────────────────────────
	writeLine(&b, "", w)            // 1 line (counted in fixedInside)
	panelTop(&b, "Event Log", w)   // 1 line (counted in fixedInside)

	last := state.Logs
	if len(last) > maxLogs {
		last = last[len(last)-maxLogs:]
	}
	for _, e := range last {
		col2, sym, lvl := logStyleFull(e.Level)
		ts := e.Time.Format("15:04:05")
		msg := e.Message
		maxMsg := w - 27
		if maxMsg > 0 && len([]rune(msg)) > maxMsg {
			msg = string([]rune(msg)[:maxMsg-1]) + "…"
		}
		line := fmt.Sprintf("%s%s%s  %s%s %s%s  %s",
			dim, ts, reset,
			col2, sym, lvl, reset,
			msg)
		panelRow(&b, line, w)
	}
	// Pad remaining log rows so the box bottom stays at a fixed position.
	for i := len(last); i < maxLogs; i++ {
		panelRow(&b, "", w)
	}
	panelBottom(&b, w) // 1 line (counted in fixedInside)

	// ── 6. Footer ─────────────────────────────────────────────────────────────
	renderFooter(&b, w, "ctrl+d  detach", "ctrl+c  stop server") // 1 line (fixedBelow)

	// Clear any leftover lines from a previous taller frame.
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

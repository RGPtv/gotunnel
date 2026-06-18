package tui

import (
	"fmt"
	"strings"
	"time"

	"github.com/RGPtv/gotunnel/internal/ipc"
)

func RunClientUI(ipcPort int) error {
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

	drawClientFrame(ipcClient)
	for {
		select {
		case <-quit:
			return nil
		case <-ticker.C:
			drawClientFrame(ipcClient)
		}
	}
}

func drawClientFrame(ipcClient *ipc.Client) {
	w, h := termSize()
	// Leave the rightmost column and bottom row empty to prevent scroll/wrap.
	w--
	h--
	if w < 60 {
		w = 60
	}
	if h < 8 {
		h = 8
	}

	var b strings.Builder

	// Home cursor without clearing — avoids full-screen flash.
	// The synchronized-output sequences in flush() make this truly atomic.
	b.WriteString("\x1b[H")

	state, err := ipcClient.GetClientState()
	if err != nil {
		renderSplash(&b, w, h, red+"  ✗  Disconnected from client"+reset)
		b.WriteString("\x1b[J")
		flush(&b)
		return
	}
	if state.Status == "" {
		renderSplash(&b, w, h, yellow+"  ◌  Connecting to GoTunnel client…"+reset)
		b.WriteString("\x1b[J")
		flush(&b)
		return
	}

	// ── 1. Header ─────────────────────────────────────────────────────────────
	renderHeader(&b, w, "GoTunnel Client", state.ServerAddr, "CLIENT") // 1 line

	// ── 2. Status strip ───────────────────────────────────────────────────────
	statusColor := lgreen
	statusIcon := "●"
	statusLabel := "ONLINE"
	if state.Status != "online" {
		statusColor = amber
		statusIcon = "◌"
		statusLabel = strings.ToUpper(state.Status)
	}

	typeLabel := " HTTP "
	typeColor := bgLblue + "\x1b[38;5;17m" + bold
	if state.TunnelType == "tcp" {
		typeLabel = " TCP  "
		typeColor = bgCyan + "\x1b[38;5;16m" + bold
	}

	statsLine := statsBadge("STATUS", statusIcon+" "+statusLabel, statusColor) +
		statsBadge("TYPE", typeLabel, typeColor) +
		statsBadge("WORKERS", fmt.Sprintf("%d", state.Workers), lteal)

	statsVis := len([]rune(strings.TrimRight(stripANSI(statsLine), " ")))
	padLen := (w - statsVis) / 2
	if padLen < 0 {
		padLen = 0
	}
	writeLine(&b, strings.Repeat(" ", padLen)+statsLine, w) // 1 line
	writeLine(&b, "", w)                                    // 1 line (spacer)

	if len(state.Tunnels) > 1 {
		drawMultiClientFrame(&b, w, h, state)
		b.WriteString("\x1b[J")
		flush(&b)
		return
	}

	// ── 3. Forwarding panel ───────────────────────────────────────────────────
	forwardingStr := ""
	if state.TunnelType == "tcp" {
		forwardingStr = fmt.Sprintf("tcp://%s → %s", state.ServerAddr+state.RemoteAddr, state.TargetAddr)
	} else {
		if state.RemoteAddr != "" {
			forwardingStr = fmt.Sprintf("https://%s.%s → %s", state.RemoteAddr, state.ServerAddr, state.TargetAddr)
		} else {
			forwardingStr = fmt.Sprintf("https://%s → %s", state.ServerAddr, state.TargetAddr)
		}
	}

	col := (w - 8) / 2

	panelTop(&b, "Tunnel Configuration", w)                                                                            // 1 line
	panelRow(&b, cfgCell(" Forwarding ", forwardingStr, w-8), w)                                                       // 1 line
	panelRow(&b, cfgCell(" Server     ", state.ServerAddr, col)+cfgCell(" Target     ", state.TargetAddr, w-8-col), w) // 1 line
	panelBottom(&b, w)                                                                                                 // 1 line
	writeLine(&b, "", w)                                                                                               // 1 line (spacer)

	// ── 4. HTTP requests table ────────────────────────────────────────────────
	//
	// Fixed lines drawn above this point:
	//   header(1) + stats(1) + spacer(1) + cfgTop(1) + cfgRows(2) + cfgBot(1) + spacer(1) = 8
	//
	// Fixed lines inside the requests panel (box chrome):
	//   reqTop(1) + reqHdr(1) + reqSep(1) + reqBot(1) = 4
	//
	// Fixed lines after variable content:
	//   footer(1) = 1
	//
	// Variable budget = h - 8 - 4 - 1 = h - 13
	const (
		fixedAbove  = 8 // lines drawn before panelTop("HTTP Request Log")
		fixedInside = 4 // box chrome: top + header row + sep + bottom
		fixedBelow  = 1 // footer
	)

	panelTop(&b, "HTTP Request Log", w) // 1 line (counted in fixedInside)

	reqsH := h - fixedAbove - fixedInside - fixedBelow
	if reqsH < 2 {
		reqsH = 2
	}

	// Column widths for the request table.
	methodW := 8
	statusW := 8
	durW := 10
	pathW := (w - 8) - methodW - statusW - durW
	if pathW < 8 {
		pathW = 8
	}

	th := dim +
		pad("METHOD", methodW) +
		pad("PATH", pathW) +
		pad("STATUS", statusW) +
		pad("DURATION", durW) + reset
	panelRow(&b, th, w) // 1 line (counted in fixedInside)
	panelSep(&b, w)     // 1 line (counted in fixedInside)

	shown := state.Requests
	var overflow int
	if len(shown) > reqsH {
		overflow = len(shown) - (reqsH - 1)
		shown = shown[len(shown)-(reqsH-1):]
	}

	for _, req := range shown {
		sColor := lgreen
		sBg := ""
		if req.Status >= 500 {
			sColor = lred
			sBg = bgLred
		} else if req.Status >= 400 {
			sColor = amber
		} else if req.Status >= 300 {
			sColor = lblue
		}

		methodColor := lgreen
		switch req.Method {
		case "POST":
			methodColor = amber
		case "PUT", "PATCH":
			methodColor = lblue
		case "DELETE":
			methodColor = lred
		}

		path := req.Path
		if len([]rune(path)) > pathW-1 {
			path = string([]rune(path)[:pathW-4]) + "…"
		}

		dur := fmt.Sprintf("%dms", req.Dur)

		line := methodColor + pad(req.Method, methodW) + reset +
			dim + pad(path, pathW) + reset +
			sBg + sColor + bold + pad(fmt.Sprintf("%d", req.Status), statusW) + reset +
			lteal + pad(dur, durW) + reset

		panelRow(&b, line, w)
	}

	// padStart tracks how many variable rows have already been written,
	// so the empty-message (if any) is counted as one of the reqsH rows
	// rather than being added on top of them.
	padStart := len(shown)
	if len(shown) == 0 {
		panelRow(&b, dim+"Waiting for requests…"+reset, w)
		padStart = 1
	}

	if overflow > 0 {
		panelRow(&b, dim+fmt.Sprintf("… and %d older requests hidden", overflow)+reset, w)
	} else {
		// Pad remaining rows so the box bottom stays at a fixed position.
		for i := padStart; i < reqsH; i++ {
			panelRow(&b, "", w)
		}
	}

	panelBottom(&b, w) // 1 line (counted in fixedInside)

	// ── 5. Footer ─────────────────────────────────────────────────────────────
	renderFooter(&b, w, "ctrl+d  detach", "ctrl+c  stop client") // 1 line (fixedBelow)

	// Clear any leftover lines from a previous taller frame.
	b.WriteString("\x1b[J")
	flush(&b)
}

func drawMultiClientFrame(b *strings.Builder, w, h int, state ipc.ClientState) {
	availableRows := h - 13
	if availableRows < 3 {
		availableRows = 3
	}

	tunnelRows := len(state.Tunnels)
	maxTunnelRows := availableRows / 2
	if maxTunnelRows < 1 {
		maxTunnelRows = 1
	}
	if tunnelRows > maxTunnelRows {
		tunnelRows = maxTunnelRows
	}

	reqsH := availableRows - tunnelRows
	if reqsH < 2 {
		reqsH = 2
	}

	renderClientTunnelTable(b, w, state.Tunnels, tunnelRows)
	writeLine(b, "", w)
	renderClientRequestLog(b, w, reqsH, state.Requests)
	renderFooter(b, w, "ctrl+d  detach", "ctrl+c  stop client")
}

func renderClientTunnelTable(b *strings.Builder, w int, tunnels []ipc.ClientTunnelState, rows int) {
	panelTop(b, "Configured Tunnels", w)

	nameW := 14
	statusW := 12
	typeW := 7
	workersW := 10
	routeW := (w - 8) - nameW - statusW - typeW - workersW
	if routeW < 8 {
		routeW = 8
	}

	header := dim +
		pad("NAME", nameW) +
		pad("STATUS", statusW) +
		pad("TYPE", typeW) +
		pad("WORKERS", workersW) +
		pad("ROUTE", routeW) + reset
	panelRow(b, header, w)
	panelSep(b, w)

	shown := tunnels
	overflow := 0
	if rows < len(shown) {
		overflow = len(shown) - rows
		shown = shown[:rows]
	}

	for _, t := range shown {
		statusColor := amber
		statusText := strings.ToUpper(t.Status)
		if t.Workers > 0 || t.Status == "online" {
			statusColor = lgreen
			statusText = "ONLINE"
		}
		if statusText == "" {
			statusText = "CONNECTING"
		}

		tunnelType := strings.ToUpper(t.TunnelType)
		if tunnelType == "" {
			tunnelType = "HTTP"
		}

		endpoint := t.RemoteAddr
		if endpoint == "" {
			endpoint = "default"
		}
		route := endpoint + " -> " + t.TargetAddr
		workers := fmt.Sprintf("%d/%d", t.Workers, t.ConfiguredWorkers)

		line := lteal + pad(t.Name, nameW) + reset +
			statusColor + bold + pad(statusText, statusW) + reset +
			dim + pad(tunnelType, typeW) + reset +
			lblue + pad(workers, workersW) + reset +
			dim + pad(route, routeW) + reset
		panelRow(b, line, w)
	}

	if overflow > 0 {
		panelRow(b, dim+fmt.Sprintf("and %d more tunnels", overflow)+reset, w)
	}

	panelBottom(b, w)
}

func renderClientRequestLog(b *strings.Builder, w, reqsH int, requests []ipc.UIRequest) {
	panelTop(b, "HTTP Request Log", w)

	methodW := 8
	statusW := 8
	durW := 10
	pathW := (w - 8) - methodW - statusW - durW
	if pathW < 8 {
		pathW = 8
	}

	header := dim +
		pad("METHOD", methodW) +
		pad("PATH", pathW) +
		pad("STATUS", statusW) +
		pad("DURATION", durW) + reset
	panelRow(b, header, w)
	panelSep(b, w)

	shown := requests
	overflow := 0
	if len(shown) > reqsH {
		overflow = len(shown) - (reqsH - 1)
		shown = shown[len(shown)-(reqsH-1):]
	}

	for _, req := range shown {
		statusColor := lgreen
		statusBg := ""
		if req.Status >= 500 {
			statusColor = lred
			statusBg = bgLred
		} else if req.Status >= 400 {
			statusColor = amber
		} else if req.Status >= 300 {
			statusColor = lblue
		}

		methodColor := lgreen
		switch req.Method {
		case "POST":
			methodColor = amber
		case "PUT", "PATCH":
			methodColor = lblue
		case "DELETE":
			methodColor = lred
		}

		line := methodColor + pad(req.Method, methodW) + reset +
			dim + pad(req.Path, pathW) + reset +
			statusBg + statusColor + bold + pad(fmt.Sprintf("%d", req.Status), statusW) + reset +
			lteal + pad(fmt.Sprintf("%dms", req.Dur), durW) + reset
		panelRow(b, line, w)
	}

	padStart := len(shown)
	if len(shown) == 0 {
		panelRow(b, dim+"Waiting for requests..."+reset, w)
		padStart = 1
	}

	if overflow > 0 {
		panelRow(b, dim+fmt.Sprintf("and %d older requests hidden", overflow)+reset, w)
	} else {
		for i := padStart; i < reqsH; i++ {
			panelRow(b, "", w)
		}
	}

	panelBottom(b, w)
}

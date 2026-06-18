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
	w--
	h--
	if w < 60 {
		w = 60
	}
	if h < 10 {
		h = 10
	}

	var b strings.Builder
	b.WriteString("\x1b[H")

	state, err := ipcClient.GetMultiClientState()
	if err != nil {
		renderSplash(&b, w, h, red+"  ✗  Disconnected from client"+reset)
		b.WriteString("\x1b[J")
		flush(&b)
		return
	}
	if len(state.Tunnels) == 0 {
		renderSplash(&b, w, h, yellow+"  ◌  Connecting to GoTunnel client…"+reset)
		b.WriteString("\x1b[J")
		flush(&b)
		return
	}

	// Aggregate stats across all tunnels.
	online := 0
	totalWorkers := 0
	serverAddr := ""
	for _, t := range state.Tunnels {
		if t.Status == "online" {
			online++
		}
		totalWorkers += t.Workers
		if serverAddr == "" {
			serverAddr = t.ServerAddr
		}
	}
	nTunnels := len(state.Tunnels)

	// ── 1. Header ─────────────────────────────────────────────────────────────
	renderHeader(&b, w, "GoTunnel Client", serverAddr, "CLIENT") // 1 line

	// ── 2. Stats strip ────────────────────────────────────────────────────────
	var statusColor, statusIcon, statusLabel string
	switch {
	case online == nTunnels:
		statusColor = lgreen
		statusIcon = "●"
		statusLabel = fmt.Sprintf("ONLINE (%d/%d)", online, nTunnels)
	case online > 0:
		statusColor = amber
		statusIcon = "◑"
		statusLabel = fmt.Sprintf("PARTIAL (%d/%d)", online, nTunnels)
	default:
		statusColor = amber
		statusIcon = "◌"
		statusLabel = "CONNECTING"
	}

	statsLine := statsBadge("STATUS", statusIcon+" "+statusLabel, statusColor) +
		statsBadge("TUNNELS", fmt.Sprintf("%d", nTunnels), lteal) +
		statsBadge("WORKERS", fmt.Sprintf("%d", totalWorkers), lteal)

	statsVis := len([]rune(strings.TrimRight(stripANSI(statsLine), " ")))
	padLen := (w - statsVis) / 2
	if padLen < 0 {
		padLen = 0
	}
	writeLine(&b, strings.Repeat(" ", padLen)+statsLine, w) // 1 line
	writeLine(&b, "", w)                                      // 1 spacer

	// ── 3. Tunnels table ──────────────────────────────────────────────────────
	//
	// Column layout (all widths in visible runes, inside the panel: w-8):
	//   NAME  TYPE  STATUS  REMOTE  TARGET  WORKERS  STREAMS
	innerW := w - 8
	nameW    := 14
	typeW    := 8
	tstatsW  := 18 // "● RECONNECTING" fits in 16, pad to 18
	remoteW  := 25
	workersW := 8
	streamsW := 8
	targetW  := innerW - nameW - typeW - tstatsW - remoteW - workersW - streamsW
	if targetW < 8 {
		targetW = 8
	}

	panelTop(&b, "Tunnels", w) // 1 line

	th := dim +
		pad("NAME", nameW) +
		pad("TYPE", typeW) +
		pad("STATUS", tstatsW) +
		pad("REMOTE/SUB", remoteW) +
		pad("TARGET", targetW) +
		pad("WORKERS", workersW) + reset
	panelRow(&b, th, w) // 1 line
	panelSep(&b, w)     // 1 line

	for _, t := range state.Tunnels {
		var sColor, sIcon string
		if t.Status == "online" {
			sColor = lgreen
			sIcon = "●"
		} else {
			sColor = amber
			sIcon = "◌"
		}

		var tColor string
		tType := strings.ToUpper(t.TunnelType)
		if t.TunnelType == "tcp" {
			tColor = cyan
		} else {
			tColor = lblue
		}

		remote := t.RemoteAddr
		if remote == "" {
			remote = "—"
		}

		statusStr := sIcon + " " + strings.ToUpper(t.Status)
		if len([]rune(statusStr)) > tstatsW-1 {
			statusStr = string([]rune(statusStr)[:tstatsW-4]) + "…"
		}

		wStr := fmt.Sprintf("%d", t.Workers)
		sStr := fmt.Sprintf("%d", t.Streams)

		row := bold + pad(t.Name, nameW) + reset +
			tColor + pad(tType, typeW) + reset +
			sColor + pad(statusStr, tstatsW) + reset +
			dim + pad(remote, remoteW) + reset +
			lteal + pad(t.TargetAddr, targetW) + reset +
			dim + rpad(wStr, workersW) + reset +
			dim + rpad(sStr, streamsW) + reset
		panelRow(&b, row, w) // 1 line per tunnel
	}

	panelBottom(&b, w) // 1 line
	writeLine(&b, "", w) // 1 spacer

	// ── 4. HTTP Request Log ───────────────────────────────────────────────────
	//
	// Fixed lines drawn so far:
	//   header(1) + stats(1) + spacer(1)
	//   + tunnelTop(1) + tunnelHdr(1) + tunnelSep(1) + nTunnels + tunnelBot(1) + spacer(1)
	//   = 8 + nTunnels
	//
	// Fixed inside request panel box chrome:
	//   reqTop(1) + reqHdr(1) + reqSep(1) + reqBot(1) = 4
	//
	// Fixed footer:
	//   footer(1) = 1
	//
	// Variable budget for request rows = h - (8+nTunnels) - 4 - 1
	fixedAbove  := 8 + nTunnels
	fixedInside := 4
	fixedBelow  := 1

	panelTop(&b, "HTTP Request Log", w) // counted in fixedInside

	reqsH := h - fixedAbove - fixedInside - fixedBelow
	if reqsH < 2 {
		reqsH = 2
	}

	// Request table column widths.
	tunnelColW := 14
	methodW    := 8
	rstatsW    := 8
	durW       := 10
	pathW      := innerW - tunnelColW - methodW - rstatsW - durW
	if pathW < 8 {
		pathW = 8
	}

	rh := dim +
		pad("TUNNEL", tunnelColW) +
		pad("METHOD", methodW) +
		pad("PATH", pathW) +
		pad("STATUS", rstatsW) +
		pad("DURATION", durW) + reset
	panelRow(&b, rh, w) // counted in fixedInside
	panelSep(&b, w)     // counted in fixedInside

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

		tunnelName := req.Tunnel
		if tunnelName == "" {
			tunnelName = "—"
		}

		line := dim + pad(tunnelName, tunnelColW) + reset +
			methodColor + pad(req.Method, methodW) + reset +
			dim + pad(path, pathW) + reset +
			sBg + sColor + bold + pad(fmt.Sprintf("%d", req.Status), rstatsW) + reset +
			lteal + pad(dur, durW) + reset
		panelRow(&b, line, w)
	}

	// Empty-state placeholder / padding.
	padStart := len(shown)
	if len(shown) == 0 {
		panelRow(&b, dim+"Waiting for requests…"+reset, w)
		padStart = 1
	}

	if overflow > 0 {
		panelRow(&b, dim+fmt.Sprintf("… and %d older requests hidden", overflow)+reset, w)
	} else {
		for i := padStart; i < reqsH; i++ {
			panelRow(&b, "", w)
		}
	}

	panelBottom(&b, w) // counted in fixedInside

	// ── 5. Footer ─────────────────────────────────────────────────────────────
	renderFooter(&b, w, "ctrl+d  detach", "ctrl+c  stop client") // fixedBelow

	b.WriteString("\x1b[J")
	flush(&b)
}

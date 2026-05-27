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
	if w < 60 {
		w = 60
	}

	var b strings.Builder

	// Move cursor to top-left without clearing — avoids the full-screen flash
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
	renderHeader(&b, w, "GoTunnel Client", state.ServerAddr, "CLIENT")

	// ── 2. Status strip ───────────────────────────────────────────────────────
	statusColor := lgreen
	statusIcon := "●"
	statusLabel := "ONLINE"
	if state.Status != "online" {
		statusColor = amber
		statusIcon = "◌"
		statusLabel = strings.ToUpper(state.Status)
	}

	typeLabel := "HTTP"
	typeColor := lblue
	if state.TunnelType == "tcp" {
		typeLabel = " TCP"
		typeColor = lpink
	}

	statsLine := "  " +
		statsBadge("STATUS", statusIcon+" "+statusLabel, statusColor) +
		statsBadge("TYPE", typeLabel, typeColor) +
		statsBadge("WORKERS", fmt.Sprintf("%d", state.Workers), lteal)

	writeLine(&b, statsLine, w)
	writeLine(&b, dim+hline(w, "─")+reset, w)

	// ── 3. Forwarding panel ───────────────────────────────────────────────────
	writeLine(&b, " "+dim+"Tunnel Configuration"+reset, w)
	writeLine(&b, dim+hline(w, "·")+reset, w)

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

	col := w / 2
	writeLine(&b, cfgCell("  Forwarding", forwardingStr, w), w)
	writeLine(&b, cfgCell("  Server    ", state.ServerAddr, col)+cfgCell("  Target    ", state.TargetAddr, w-col), w)
	writeLine(&b, dim+hline(w, "─")+reset, w)

	// ── 4. HTTP requests table ────────────────────────────────────────────────
	writeLine(&b, " "+dim+"HTTP Request Log"+reset, w)

	// Lines used: 1(hdr)+1(stats)+1(sep)+1(cfg-label)+1(cfg-dot)+2(cfg-rows)+1(sep)+1(req-label) = 9
	// Footer = 1
	const (
		usedLines = 9
		footerH   = 1
	)
	reqsH := h - usedLines - footerH - 3 // 3 = table header + dot + sep
	if reqsH < 2 {
		reqsH = 2
	}

	methodW := 8
	statusW := 8
	durW := 10
	pathW := w - methodW - statusW - durW - 4

	th := dim + "  " +
		pad("METHOD", methodW) +
		pad("PATH", pathW) +
		pad("STATUS", statusW) +
		pad("DURATION", durW) + reset
	writeLine(&b, th, w)
	writeLine(&b, dim+hline(w, "·")+reset, w)

	shown := state.Requests
	if len(shown) > reqsH {
		shown = shown[len(shown)-reqsH:]
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
		if len(path) > pathW-1 {
			path = path[:pathW-4] + "…"
		}

		dur := fmt.Sprintf("%dms", req.Dur)

		line := "  " +
			methodColor + pad(req.Method, methodW) + reset +
			dim + pad(path, pathW) + reset +
			sBg + sColor + bold + pad(fmt.Sprintf("%d", req.Status), statusW) + reset +
			lteal + pad(dur, durW) + reset

		writeLine(&b, line, w)
	}

	if len(shown) == 0 {
		writeLine(&b, dim+"  Waiting for requests…"+reset, w)
	}

	for i := len(shown); i < reqsH; i++ {
		writeLine(&b, "", w)
	}

	writeLine(&b, dim+hline(w, "─")+reset, w)

	// ── 5. Footer ─────────────────────────────────────────────────────────────
	renderFooter(&b, w, "ctrl+d  detach", "ctrl+c  stop client")

	b.WriteString("\x1b[J")
	flush(&b)
}

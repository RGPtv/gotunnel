package tui

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/RGPtv/gotunnel/internal/ipc"
)

func RunClientUI(ipcPort int) error {
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

	renderClientUI(ipcClient)

	for {
		select {
		case <-quit:
			return nil
		case <-ticker.C:
			renderClientUI(ipcClient)
		}
	}
}

func renderClientUI(ipcClient *ipc.Client) {
	state, err := ipcClient.GetClientState()
	w, h := termSize()
	if w < 60 {
		w = 60
	}

	var b strings.Builder
	b.WriteString(esc + "H")

	// ── connecting / error states ─────────────────────────────────────────────
	if err != nil {
		renderSplash(&b, w, h, red+"  ✗  Disconnected from client"+reset, "")
		b.WriteString(esc + "J")
		fmt.Fprint(os.Stdout, b.String())
		return
	}
	if state.Status == "" {
		renderSplash(&b, w, h, yellow+"  ◌  Connecting to GoTunnel client…"+reset, "")
		b.WriteString(esc + "J")
		fmt.Fprint(os.Stdout, b.String())
		return
	}

	// ── header ────────────────────────────────────────────────────────────────
	renderHeader(&b, w, "GoTunnel Client", state.ServerAddr, "CLIENT")

	// ── status strip ──────────────────────────────────────────────────────────
	statusColor := "\x1b[38;5;82m" // bright green
	statusIcon := "●"
	statusLabel := "ONLINE"
	if state.Status != "online" {
		statusColor = "\x1b[38;5;214m" // amber
		statusIcon = "◌"
		statusLabel = strings.ToUpper(state.Status)
	}

	typeLabel := "HTTP"
	typeColor := "\x1b[38;5;39m"
	if state.TunnelType == "tcp" {
		typeLabel = " TCP"
		typeColor = "\x1b[38;5;213m"
	}

	statsLine := fmt.Sprintf(
		"  %s STATUS %s%s %s%s   %s TYPE %s%s%s   %s WORKERS %s%d%s",
		dim+"┃"+reset, statusColor+bold, statusIcon, statusLabel, reset,
		dim+"┃"+reset, typeColor+bold, typeLabel, reset,
		dim+"┃"+reset, "\x1b[38;5;123m"+bold, state.Workers, reset,
	)
	writeLine(&b, statsLine, w)
	writeLine(&b, dim+strings.Repeat("─", w)+reset, w)

	// ── forwarding panel ──────────────────────────────────────────────────────
	writeLine(&b, " "+dim+"Tunnel Configuration"+reset, w)
	writeLine(&b, dim+strings.Repeat("·", w)+reset, w)

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
	row1 := cfgCell("  Forwarding", forwardingStr, w)
	row2 := cfgCell("  Server    ", state.ServerAddr, col) + cfgCell("  Target    ", state.TargetAddr, w-col)

	writeLine(&b, row1, w)
	writeLine(&b, row2, w)

	writeLine(&b, dim+strings.Repeat("─", w)+reset, w)

	// ── HTTP requests table ───────────────────────────────────────────────────
	writeLine(&b, " "+dim+"HTTP Request Log"+reset, w)

	headerH := 11
	separators := 4
	reqsH := h - headerH - separators
	if reqsH < 2 {
		reqsH = 2
	}

	methodW := 8
	statusW := 8
	durW := 10
	pathW := w - methodW - statusW - durW - 5

	th := dim +
		"  " + pad("METHOD", methodW) +
		pad("PATH", pathW) +
		pad("STATUS", statusW) +
		pad("DURATION", durW) +
		reset
	writeLine(&b, th, w)
	writeLine(&b, dim+strings.Repeat("·", w)+reset, w)

	shown := state.Requests
	if len(shown) > reqsH {
		shown = shown[len(shown)-reqsH:]
	}

	for _, req := range shown {
		sColor := "\x1b[38;5;82m" // green
		sBg := ""
		if req.Status >= 500 {
			sColor = "\x1b[38;5;196m"
			sBg = "\x1b[48;5;52m"
		} else if req.Status >= 400 {
			sColor = "\x1b[38;5;214m"
		} else if req.Status >= 300 {
			sColor = "\x1b[38;5;39m"
		}

		methodColor := "\x1b[38;5;82m"
		switch req.Method {
		case "POST":
			methodColor = "\x1b[38;5;214m"
		case "PUT", "PATCH":
			methodColor = "\x1b[38;5;39m"
		case "DELETE":
			methodColor = "\x1b[38;5;196m"
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
			dim + pad(dur, durW) + reset

		writeLine(&b, line, w)
	}

	if len(shown) == 0 {
		writeLine(&b, dim+"  Waiting for requests…"+reset, w)
	}

	for i := len(shown); i < reqsH; i++ {
		writeLine(&b, "", w)
	}

	// ── footer / keybind bar ──────────────────────────────────────────────────
	renderFooter(&b, w, "ctrl+d  detach", "ctrl+c  stop client")

	b.WriteString(esc + "J")
	fmt.Fprint(os.Stdout, b.String())
}

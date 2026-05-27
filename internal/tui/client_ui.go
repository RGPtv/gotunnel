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

	var b strings.Builder
	b.WriteString(esc + "H")

	if err != nil {
		b.WriteString(fmt.Sprintf("\n%s  Disconnected from client: %v%s\n", red, err, reset))
		b.WriteString(esc + "J")
		fmt.Fprint(os.Stdout, b.String())
		return
	}
	if state.Status == "" {
		b.WriteString("\n  Connecting to gotunnel client daemon...\n")
		b.WriteString(esc + "J")
		fmt.Fprint(os.Stdout, b.String())
		return
	}

	// ── header bar ───────────────────────────────────────────────────────────
	title := "  GoTunnel Client "
	header := bold + bgCyan + " " + title + reset
	header += strings.Repeat(" ", max(0, w-len(title)-3))
	writeLine(&b, header, w)
	b.WriteString(dim + hline(w, "─") + reset + "\n")

	// ── info pane ─────────────────────────────────────────────────────────────
	statusColor := green
	if state.Status != "online" {
		statusColor = yellow
	}

	forwardingStr := ""
	if state.TunnelType == "tcp" {
		forwardingStr = fmt.Sprintf("tcp://%s -> %s", state.ServerAddr+state.RemoteAddr, state.TargetAddr)
	} else {
		if state.RemoteAddr != "" {
			forwardingStr = fmt.Sprintf("https://%s.%s -> %s", state.RemoteAddr, state.ServerAddr, state.TargetAddr)
		} else {
			forwardingStr = fmt.Sprintf("https://%s -> %s", state.ServerAddr, state.TargetAddr)
		}
	}

	row1 := "  Status     : " + statusColor + state.Status + reset
	row2 := "  Forwarding : " + cyan + forwardingStr + reset
	row3 := fmt.Sprintf("  Workers    : %s%d%s", cyan, state.Workers, reset)

	writeLine(&b, row1, w)
	writeLine(&b, row2, w)
	writeLine(&b, row3, w)

	b.WriteString(dim + hline(w, "─") + reset + "\n")

	// ── requests pane ─────────────────────────────────────────────────────────
	writeLine(&b, dim+"  HTTP Requests"+reset, w)

	reqsH := h - 9 - 2
	if reqsH < 3 {
		reqsH = 3
	}

	th := bold + dim +
		" " + pad("METHOD", 8) +
		pad("PATH", 40) +
		pad("STATUS", 8) +
		pad("DURATION", 10) +
		reset
	writeLine(&b, th, w)
	b.WriteString(dim + hline(w, "·") + reset + "\n")

	shown := state.Requests
	if len(shown) > reqsH-2 {
		shown = shown[len(shown)-(reqsH-2):]
	}

	for _, req := range shown {
		color := green
		if req.Status >= 500 {
			color = red
		} else if req.Status >= 400 {
			color = yellow
		} else if req.Status >= 300 {
			color = cyan
		}

		path := req.Path
		if len(path) > 37 {
			path = path[:34] + "..."
		}

		line := " " +
			pad(req.Method, 8) +
			pad(path, 40) +
			color + pad(fmt.Sprintf("%d", req.Status), 8) + reset +
			cyan + pad(fmt.Sprintf("%dms", req.Dur), 10) + reset

		writeLine(&b, line, w)
	}

	for i := len(shown); i < reqsH-2; i++ {
		writeLine(&b, "", w)
	}

	b.WriteString(dim + hline(w, "─") + reset + "\n")

	// ── help bar ──────────────────────────────────────────────────────────────
	writeLine(&b, dim+"  ctrl+d: detach • ctrl+c: stop client"+reset, w)

	b.WriteString(esc + "J")
	fmt.Fprint(os.Stdout, b.String())
}

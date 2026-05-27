package tui

import (
	"fmt"
	"strings"
	"time"

	"github.com/RGPtv/gotunnel/internal/ipc"
	"github.com/charmbracelet/bubbles/table"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

var (
	baseStyle = lipgloss.NewStyle().BorderStyle(lipgloss.NormalBorder()).BorderForeground(lipgloss.Color("240"))
	titleStyle = lipgloss.NewStyle().Background(lipgloss.Color("62")).Foreground(lipgloss.Color("230")).Padding(0, 1).Bold(true)
	infoStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("86"))
	warnStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("214"))
	errStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("196"))
	succStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("42"))
	dimStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("240"))
)

type serverModel struct {
	ipcClient *ipc.Client
	state     ipc.ServerState
	table     table.Model
	viewport  viewport.Model
	width     int
	height    int
	err       error
}

func RunServerUI(ipcPort int) error {
	columns := []table.Column{
		{Title: "ENDPOINT", Width: 25},
		{Title: "TYPE", Width: 6},
		{Title: "CONNS", Width: 8},
		{Title: "CLIENT IP", Width: 20},
		{Title: "PROXY URL", Width: 30},
	}
	t := table.New(table.WithColumns(columns), table.WithHeight(10))
	s := table.DefaultStyles()
	s.Header = s.Header.BorderStyle(lipgloss.NormalBorder()).BorderForeground(lipgloss.Color("240")).BorderBottom(true).Bold(false)
	s.Selected = s.Selected.Foreground(lipgloss.Color("229")).Background(lipgloss.Color("57")).Bold(false)
	t.SetStyles(s)

	vp := viewport.New(100, 10)

	m := serverModel{
		ipcClient: ipc.NewClient(ipcPort),
		table:     t,
		viewport:  vp,
	}

	p := tea.NewProgram(m, tea.WithAltScreen())
	_, err := p.Run()
	return err
}

func (m serverModel) Init() tea.Cmd {
	return tickCmd()
}

type tickMsg time.Time

func tickCmd() tea.Cmd {
	return tea.Tick(time.Millisecond*500, func(t time.Time) tea.Msg {
		return tickMsg(t)
	})
}

func (m serverModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+d":
			return m, tea.Quit
		case "ctrl+c":
			m.ipcClient.Shutdown()
			return m, tea.Quit
		case "up", "k":
			m.table, cmd = m.table.Update(msg)
			return m, cmd
		case "down", "j":
			m.table, cmd = m.table.Update(msg)
			return m, cmd
		}
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.viewport.Width = msg.Width - 4
		m.viewport.Height = 10
	case tickMsg:
		state, err := m.ipcClient.GetServerState()
		if err != nil {
			m.err = err
			// If daemon exits, we exit after a moment
			return m, tea.Quit
		}
		m.err = nil
		m.state = state

		// update table
		var rows []table.Row
		for _, tun := range state.Tunnels {
			rows = append(rows, table.Row{
				tun.Endpoint,
				tun.Type,
				fmt.Sprintf("%d", tun.Connections),
				tun.ClientIP,
				tun.ProxyURL,
			})
		}
		m.table.SetRows(rows)

		// update viewport (logs)
		var logLines []string
		for _, l := range state.Logs {
			ts := l.Time.Format("15:04:05")
			msg := l.Message
			// Apply basic colors based on level
			var prefix string
			switch l.Level {
			case 0: // info
				prefix = dimStyle.Render(ts) + infoStyle.Render(" · ")
			case 1: // warn
				prefix = dimStyle.Render(ts) + warnStyle.Render(" ! ")
			case 2: // error
				prefix = dimStyle.Render(ts) + errStyle.Render(" ✗ ")
			case 3: // success
				prefix = dimStyle.Render(ts) + succStyle.Render(" ✓ ")
			}
			logLines = append(logLines, prefix+msg)
		}
		m.viewport.SetContent(strings.Join(logLines, "\n"))
		m.viewport.GotoBottom()
		
		return m, tickCmd()
	}
	return m, nil
}

func (m serverModel) View() string {
	if m.err != nil {
		return errStyle.Render(fmt.Sprintf("\n  Disconnected from server: %v\n", m.err))
	}
	if m.state.Token == "" {
		return "\n  Connecting to gotunnel server...\n"
	}

	uptimeStr := (time.Duration(m.state.Uptime) * time.Second).String()
	
	header := lipgloss.JoinHorizontal(lipgloss.Center,
		titleStyle.Render(" gotunnel server "),
		"  ",
		dimStyle.Render("uptime "+uptimeStr),
	)

	inspectUrl := "—"
	if m.state.InspectAddr != "" {
		inspectUrl = "http://" + m.state.InspectAddr
	}

	info := fmt.Sprintf(`HTTP Proxy : %s
HTTPS Proxy: %s
Tunnel Port: %s
Token      : %s

Dashboard  : %s
Login      : %s / %s

Active Conns: %d
Total Reqs  : %d`,
		infoStyle.Render(m.state.HTTPAddr),
		infoStyle.Render(m.state.HTTPSAddr),
		infoStyle.Render(m.state.TunAddr),
		m.state.Token,
		infoStyle.Render(inspectUrl),
		m.state.DashUser, m.state.DashPass,
		m.state.ActiveConns,
		m.state.TotalReqs,
	)

	tableView := baseStyle.Render(m.table.View())
	logView := baseStyle.Render(m.viewport.View())

	help := dimStyle.Render("  ↑/↓: scroll table • ctrl+d: detach • ctrl+c: stop server")

	return fmt.Sprintf("\n%s\n\n%s\n\n%s\n\n%s\n\n%s", header, info, tableView, logView, help)
}

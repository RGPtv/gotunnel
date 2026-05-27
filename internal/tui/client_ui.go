package tui

import (
	"fmt"
	"time"

	"github.com/RGPtv/gotunnel/internal/ipc"
	"github.com/charmbracelet/bubbles/table"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

type clientModel struct {
	ipcClient *ipc.Client
	state     ipc.ClientState
	table     table.Model
	width     int
	height    int
	err       error
}

func RunClientUI(ipcPort int) error {
	columns := []table.Column{
		{Title: "METHOD", Width: 8},
		{Title: "PATH", Width: 40},
		{Title: "STATUS", Width: 8},
		{Title: "DURATION", Width: 10},
	}
	t := table.New(table.WithColumns(columns), table.WithHeight(10))
	s := table.DefaultStyles()
	s.Header = s.Header.BorderStyle(lipgloss.NormalBorder()).BorderForeground(lipgloss.Color("240")).BorderBottom(true).Bold(false)
	s.Selected = s.Selected.Foreground(lipgloss.Color("229")).Background(lipgloss.Color("57")).Bold(false)
	t.SetStyles(s)

	m := clientModel{
		ipcClient: ipc.NewClient(ipcPort),
		table:     t,
	}

	p := tea.NewProgram(m, tea.WithAltScreen())
	_, err := p.Run()
	return err
}

func (m clientModel) Init() tea.Cmd {
	return tickClientCmd()
}

func tickClientCmd() tea.Cmd {
	return tea.Tick(time.Millisecond*500, func(t time.Time) tea.Msg {
		return tickMsg(t)
	})
}

func (m clientModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
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
	case tickMsg:
		state, err := m.ipcClient.GetClientState()
		if err != nil {
			m.err = err
			return m, tea.Quit
		}
		m.err = nil
		m.state = state

		// update table
		var rows []table.Row
		for _, req := range state.Requests {
			color := "42" // green
			if req.Status >= 500 {
				color = "196" // red
			} else if req.Status >= 400 {
				color = "214" // yellow
			} else if req.Status >= 300 {
				color = "86" // cyan
			}
			
			statusStr := lipgloss.NewStyle().Foreground(lipgloss.Color(color)).Render(fmt.Sprintf("%d", req.Status))

			path := req.Path
			if len(path) > 40 {
				path = path[:37] + "..."
			}

			rows = append(rows, table.Row{
				req.Method,
				path,
				statusStr,
				fmt.Sprintf("%dms", req.Dur),
			})
		}
		m.table.SetRows(rows)
		
		return m, tickClientCmd()
	}
	return m, nil
}

func (m clientModel) View() string {
	if m.err != nil {
		return errStyle.Render(fmt.Sprintf("\n  Disconnected from client: %v\n", m.err))
	}
	if m.state.Status == "" {
		return "\n  Connecting to gotunnel client daemon...\n"
	}

	header := lipgloss.JoinHorizontal(lipgloss.Center,
		titleStyle.Render(" gotunnel client "),
	)

	statusColor := succStyle
	if m.state.Status != "online" {
		statusColor = warnStyle
	}

	forwardingStr := ""
	if m.state.TunnelType == "tcp" {
		forwardingStr = fmt.Sprintf("tcp://%s -> %s", m.state.ServerAddr+m.state.RemoteAddr, m.state.TargetAddr)
	} else {
		if m.state.RemoteAddr != "" {
			forwardingStr = fmt.Sprintf("https://%s.%s -> %s", m.state.RemoteAddr, m.state.ServerAddr, m.state.TargetAddr)
		} else {
			forwardingStr = fmt.Sprintf("https://%s -> %s", m.state.ServerAddr, m.state.TargetAddr)
		}
	}

	info := fmt.Sprintf(`Status          : %s
Forwarding      : %s
Active Workers  : %d`,
		statusColor.Render(m.state.Status),
		infoStyle.Render(forwardingStr),
		m.state.Workers,
	)

	tableView := baseStyle.Render(m.table.View())
	help := dimStyle.Render("  ↑/↓: scroll table • ctrl+d: detach • ctrl+c: stop client")

	return fmt.Sprintf("\n%s\n\n%s\n\n  HTTP Requests\n%s\n\n%s", header, info, tableView, help)
}

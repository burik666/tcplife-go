package main

import (
	"fmt"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

const (
	refreshInterval = 250 * time.Millisecond
	rxColor         = tcell.ColorGreen
	txColor         = tcell.ColorTeal
	totalColor      = tcell.ColorYellow
	nameColor       = tcell.ColorWhite
	timeColor       = tcell.ColorGray
	activeColor     = tcell.ColorLightGreen
)

type collapseRef struct{ key string }

type tui struct {
	app     *tview.Application
	pages   *tview.Pages
	table   *tview.Table
	filter  *tview.InputField
	summary *tview.TextView
	footer  *tview.TextView

	store *Store
	cap   *capture

	group GroupMode
	sort  SortMode
	asc   bool
	proto ProtoMode

	// flt is the compiled filter pattern, refreshed on filter input so the
	// regexp is not recompiled on every refresh tick.
	flt textFilter

	// lastRows is the row list currently rendered by the table; it maps
	// selection indexes to entities between rebuilds. Only touched inside
	// rebuild() (main loop), so no locking is needed.
	lastRows []viewRow

	// rateW is the widest rate string seen so far; rate cells are padded to
	// it so RX/s and TX/s columns only ever grow, never shrink.
	rateW int

	layout string

	collapsed map[string]bool

	paused atomic.Bool

	groupList *tview.List
	sortList  *tview.List

	modalName string

	started time.Time
}

// runTUI starts the interactive terminal UI, owning the ring-buffer reader.
func runTUI(c *capture, layout string) {
	m := &tui{
		app:       tview.NewApplication(),
		store:     NewStore(),
		cap:       c,
		group:     GroupFlat,
		sort:      SortTime,
		asc:       false,
		layout:    layout,
		collapsed: map[string]bool{},
		started:   time.Now(),
	}

	m.buildUI()
	m.buildModals()
	m.rebuild()
	m.app.SetFocus(m.table)

	go func() {
		for {
			sess, err := c.readEvent()
			if err != nil {
				return
			}
			m.store.Upsert(sess)
		}
	}()

	go func() {
		tick := time.NewTicker(refreshInterval)
		defer tick.Stop()

		for range tick.C {
			if m.paused.Load() {
				continue
			}
			// Advance live rates so idle connections decay toward 0 even
			// between events, then rebuild on new data or while active so
			// live durations and rates keep moving.
			active := m.store.HasActive()
			if active {
				m.store.Tick(time.Now())
			}
			if m.store.takeDirty() || active {
				m.app.QueueUpdateDraw(m.rebuild)
			}
		}
	}()

	onShutdown(func() {
		c.rd.Close()
		m.app.Stop()
	})

	if err := m.app.Run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func (m *tui) buildUI() {
	root := tview.NewFlex().SetDirection(tview.FlexRow)

	m.summary = tview.NewTextView().SetDynamicColors(true)

	m.table = tview.NewTable().
		SetSelectable(true, false).
		SetFixed(1, 0).
		SetSelectedStyle(tcell.StyleDefault.
			Background(tcell.ColorDarkSlateGray).
			Foreground(tcell.ColorWhite))

	m.table.SetSelectedFunc(func(row, col int) {
		if ref, ok := m.cellRef(row); ok {
			m.toggleCollapse(ref.key)
		}
	})

	m.filter = tview.NewInputField().
		SetLabel(" filter › ").
		SetFieldWidth(0).
		SetLabelColor(timeColor).
		SetFieldStyle(tcell.StyleDefault.Background(tcell.ColorDefault).Foreground(nameColor)).
		SetPlaceholderStyle(tcell.StyleDefault.Background(tcell.ColorDefault).Foreground(timeColor)).
		SetPlaceholder("pid / command / address / state — regexp, Esc clears").
		SetChangedFunc(func(text string) {
			m.flt = compileFilter(text)
			m.rebuild()
		}).
		SetDoneFunc(func(tcell.Key) {
			m.app.SetFocus(m.table)
		})

	m.footer = tview.NewTextView().SetDynamicColors(true)
	m.footer.SetText(footerText())

	root.
		AddItem(m.summary, 2, 0, false).
		AddItem(m.table, 0, 1, true).
		AddItem(m.filter, 1, 0, false).
		AddItem(m.footer, 1, 0, false)

	m.pages = tview.NewPages().AddPage("main", root, true, true)

	m.app.SetRoot(m.pages, true).EnableMouse(true)
	m.app.SetInputCapture(m.onKey)
}

func footerText() string {
	return "    [yellow]/[white] filter    [yellow]t[white] tcp/udp    [yellow]g[white] group    " +
		"[yellow]s[white] sort    [yellow]r[white] asc/desc    [yellow]space[white] collapse    " +
		"[yellow]p[white] pause    [yellow]c[white] clear    [yellow]q[white] quit"
}

func (m *tui) cellRef(row int) (*collapseRef, bool) {
	cell := m.table.GetCell(row, 0)
	if cell == nil {
		return nil, false
	}

	ref, ok := cell.Reference.(*collapseRef)

	return ref, ok
}

func (m *tui) onKey(ev *tcell.EventKey) *tcell.EventKey {
	if m.modalName != "" {
		if ev.Key() == tcell.KeyEscape {
			m.closeModal()
			return nil
		}
		return ev
	}

	if m.app.GetFocus() == m.filter {
		if ev.Key() == tcell.KeyEscape {
			m.filter.SetText("")
			m.app.SetFocus(m.table)
			return nil
		}
		return ev
	}

	if ev.Key() == tcell.KeyCtrlC {
		m.quit()
		return nil
	}

	if ev.Key() == tcell.KeyRune {
		return m.onRune(ev)
	}

	return ev
}

func (m *tui) onRune(ev *tcell.EventKey) *tcell.EventKey {
	switch ev.Rune() {
	case 'q':
		m.quit()
	case '/':
		m.app.SetFocus(m.filter)
	case 'g':
		m.openModal("group")
	case 's':
		m.openModal("sort")
	case 't':
		m.cycleProto()
		m.rebuild()
	case 'r':
		m.asc = !m.asc
		m.rebuild()
	case 'p':
		m.paused.Store(!m.paused.Load())
		m.rebuild()
	case 'c':
		m.store.Clear()
		m.collapsed = map[string]bool{}
		m.rebuild()
	case ' ':
		m.collapseSelected()
	case '+', '=':
		m.collapseAll(false)
	case '-':
		m.collapseAll(true)
	default:
		return ev
	}

	return nil
}

func (m *tui) quit() {
	m.cap.rd.Close()
	m.app.Stop()
}

// cycleProto advances the protocol filter All -> TCP -> UDP -> All.
func (m *tui) cycleProto() {
	switch m.proto {
	case ProtoAll:
		m.proto = ProtoTCP
	case ProtoTCP:
		m.proto = ProtoUDP
	default:
		m.proto = ProtoAll
	}
}

func (m *tui) toggleCollapse(key string) {
	m.collapsed[key] = !m.collapsed[key]
	m.rebuild()
}

func (m *tui) collapseSelected() {
	row, _ := m.table.GetSelection()
	if ref, ok := m.cellRef(row); ok {
		m.toggleCollapse(ref.key)
	}
}

func (m *tui) collapseAll(collapse bool) {
	if !collapse {
		m.collapsed = map[string]bool{}
	} else {
		for _, r := range m.viewRows() {
			if r.isGroup {
				m.collapsed[r.groupKey] = true
			}
		}
	}

	m.rebuild()
}

func (m *tui) viewRows() []viewRow {
	return buildView(m.store.Snapshot(), viewOptions{
		group:     m.group,
		sort:      m.sort,
		asc:       m.asc,
		filter:    m.flt,
		proto:     m.proto,
		collapsed: m.collapsed,
		now:       time.Now(),
	})
}

func (m *tui) rebuild() {
	origSel, col := m.table.GetSelection()
	offRow, offCol := m.table.GetOffset()

	// Resolve the cursor against the row list that is currently displayed
	// (m.lastRows): the new view may already contain freshly arrived
	// connections, so indexing it with the old selection would describe a
	// different row.
	target := selectionKey(m.lastRows, origSel)

	rows := m.viewRows()

	if w := measureRateWidth(rows); w > m.rateW {
		m.rateW = w
	}

	m.table.Clear()
	m.renderHeader()

	for i, r := range rows {
		if r.isGroup {
			m.renderGroupRow(i+1, r)
		} else {
			m.renderSessionRow(i+1, r)
		}
	}

	sel := restoreSel(rows, origSel, target)
	if sel > m.table.GetRowCount()-1 {
		sel = m.table.GetRowCount() - 1
	}

	m.lastRows = rows
	m.table.Select(sel, col)
	m.table.SetOffset(offRow, offCol)
	m.summary.SetText(m.summaryText())
}

// restoreSel maps the old selection index (identified by target, resolved
// against the previously rendered rows) onto the new row list, keeping the
// cursor on the same entity. Falls back to origSel when it no longer exists.
func restoreSel(rows []viewRow, origSel int, target string) int {
	if target == "" {
		return origSel
	}

	for i := range rows {
		if selectionKey(rows, i+1) == target {
			return i + 1
		}
	}

	return origSel
}

// selectionKey identifies the table row at sel ("G|<key>" for group rows,
// "S|<id>" for session rows); "" when nothing selectable is pointed at.
func selectionKey(rows []viewRow, sel int) string {
	if sel < 1 || sel > len(rows) {
		return ""
	}

	r := rows[sel-1]
	if r.isGroup {
		return "G|" + r.groupKey
	}
	return fmt.Sprintf("S|%d", r.ID)
}

// measureRateWidth returns the display width of the widest rate string that
// would be shown in the RX/s and TX/s columns for these rows (0 B/s counts
// for active sessions; blank cells do not contribute).
func measureRateWidth(rows []viewRow) int {
	w := 0

	for _, r := range rows {
		if r.isGroup {
			if r.RxRate > 0 {
				w = max(w, len(humanRate(r.RxRate)))
			}

			if r.TxRate > 0 {
				w = max(w, len(humanRate(r.TxRate)))
			}

			continue
		}

		if r.Active {
			w = max(w, len(humanRate(r.RxRate)), len(humanRate(r.TxRate)))
		}
	}

	return w
}

// padRate left-pads s to width w so rate columns keep a constant size.
func padRate(s string, w int) string {
	if len(s) >= w {
		return s
	}

	return strings.Repeat(" ", w-len(s)) + s
}

// rateVisible reports whether an active row's rate cells should be shown:
// UDP flows stay blank while both rates are zero.
func rateVisible(proto string, rxRate, txRate uint64) bool {
	if proto == "UDP" && rxRate == 0 && txRate == 0 {
		return false
	}

	return true
}

func (m *tui) renderHeader() {
	headers := []string{
		"TIME", "DURATION", "PID", "PROTO", "LADDR", "RADDR",
		"RX", "TX", "RX/s", "TX/s", "STATE", "COMMAND",
	}
	aligns := []int{
		tview.AlignLeft, tview.AlignRight, tview.AlignLeft, tview.AlignLeft, tview.AlignLeft, tview.AlignLeft,
		tview.AlignRight, tview.AlignRight, tview.AlignRight, tview.AlignRight,
		tview.AlignLeft, tview.AlignLeft,
	}

	marked := make(map[int]bool)
	for _, c := range sortColumns(m.sort) {
		marked[c] = true
	}

	for c, h := range headers {
		if marked[c] {
			h += " " + dirArrow(m.asc)
		}

		cell := tview.NewTableCell(h).
			SetAlign(aligns[c]).
			SetStyle(tcell.StyleDefault.Bold(true).Foreground(rxColor))
		m.table.SetCell(0, c, cell)
	}
}

func (m *tui) renderSessionRow(idx int, r viewRow) {
	// r.Dur is already the effective (live) duration from buildView.
	dur := r.Dur

	timeCell := formatTime(r.Time, m.layout)
	timeCol := timeColor

	if r.Active {
		timeCol = activeColor
	}

	m.table.SetCell(idx, colTime, colorCell(timeCell, timeCol, tview.AlignLeft))
	m.table.SetCell(idx, colDur, rightCell(humanDuration(dur)))
	m.table.SetCell(idx, colPID, plainCell(formatPID(r.PID)))
	m.table.SetCell(idx, colProto, plainCell(r.Proto))
	m.table.SetCell(idx, colLaddr, plainCell(r.Laddr))
	m.table.SetCell(idx, colRaddr, plainCell(directionArrow(r.Out)+r.Raddr))
	m.table.SetCell(idx, colRX, colorCell(humanBytes(r.RX), rxColor, tview.AlignRight))
	m.table.SetCell(idx, colTX, colorCell(humanBytes(r.TX), txColor, tview.AlignRight))
	m.renderRateCells(idx, r)

	m.table.SetCell(idx, colState, colorCell(r.State, stateColor(r.State), tview.AlignLeft))
	m.table.SetCell(idx, colComm, plainCell(r.Comm))
}

// renderRateCells draws the padded RX/s and TX/s cells for a session row:
// values when the active row's rates are visible, blanks otherwise.
func (m *tui) renderRateCells(idx int, r viewRow) {
	visible := r.Active && rateVisible(r.Proto, r.RxRate, r.TxRate)

	rx, tx := "", ""
	if visible {
		rx, tx = humanRate(r.RxRate), humanRate(r.TxRate)
	}

	rxCell := rightCell(padRate(rx, m.rateW))
	txCell := rightCell(padRate(tx, m.rateW))

	if visible {
		rxCell.SetTextColor(rxColor)
		txCell.SetTextColor(txColor)
	}

	m.table.SetCell(idx, colRxRate, rxCell)
	m.table.SetCell(idx, colTxRate, txCell)
}

// stateColor tints the STATE cell: green when established, blue while
// handshaking, yellow during teardown, gray otherwise.
func stateColor(state string) tcell.Color {
	switch state {
	case "ESTABLISHED":
		return activeColor
	case "SYN_SENT", "SYN_RECV", "NEW_SYN_RECV", "LISTEN":
		return tcell.ColorDodgerBlue
	case "FIN_WAIT1", "FIN_WAIT2", "CLOSING", "LAST_ACK", "CLOSE_WAIT":
		return totalColor
	default:
		return timeColor
	}
}

func (m *tui) renderGroupRow(idx int, r viewRow) {
	marker := "▼ "
	if r.collapsed {
		marker = "▶ "
	}

	label := fmt.Sprintf("%s%s  (%d)", marker, r.name, r.count)

	ref := &collapseRef{key: r.groupKey}

	for c := range colCount {
		switch {
		case c == colTime:
			cell := tview.NewTableCell(formatTime(r.Time, m.layout)).
				SetAlign(tview.AlignLeft).
				SetTextColor(timeColor).
				SetReference(ref)
			m.table.SetCell(idx, c, cell)
		case c == r.nameCol:
			cell := tview.NewTableCell(label).
				SetAlign(tview.AlignLeft).
				SetStyle(tcell.StyleDefault.Bold(true).Foreground(nameColor)).
				SetReference(ref)
			m.table.SetCell(idx, c, cell)
		default:
			m.table.SetCell(idx, c, tview.NewTableCell(""))
		}
	}

	m.table.SetCell(idx, colRX, boldCell(humanBytes(r.RX), totalColor))
	m.table.SetCell(idx, colTX, boldCell(humanBytes(r.TX), totalColor))

	rxRate := ""
	if r.RxRate > 0 {
		rxRate = humanRate(r.RxRate)
	}

	txRate := ""
	if r.TxRate > 0 {
		txRate = humanRate(r.TxRate)
	}

	m.table.SetCell(idx, colRxRate, boldCell(padRate(rxRate, m.rateW), totalColor))
	m.table.SetCell(idx, colTxRate, boldCell(padRate(txRate, m.rateW), totalColor))

	m.table.SetCell(idx, colDur, boldCell(humanDuration(r.Dur), totalColor))
}

func (m *tui) summaryText() string {
	count, active, rx, tx := m.store.Stats()
	rxRate, txRate := m.store.Rates()

	up := time.Since(m.started).Truncate(time.Second)

	sort := fmt.Sprintf("%s %s", m.sort.String(), dirArrow(m.asc))

	conns := fmt.Sprintf("conns %d", count)
	if active > 0 {
		conns = fmt.Sprintf("[lightgreen]%d active[::-] · closed %d", active, count-active)
	}

	extra := ""
	if m.paused.Load() {
		extra += "  [red::b]PAUSED[::-]"
	}

	if f := m.filter.GetText(); f != "" {
		switch {
		case m.flt.err != nil:
			extra += "  [red::b]filter: " + tview.Escape(f) + " (invalid regexp)[::-]"
		default:
			extra += "  [gray]filter:[::-] [yellow]" + tview.Escape(f) + "[::-]"
		}
	}

	return fmt.Sprintf(
		"[white::b]tcplife-go[::-]  up %s  ·  %s  ·  [green]RX %s[::-]  ·  [teal]TX %s[::-]  ·  [green]RX/s %s[::-]  ·  [teal]TX/s %s[::-]\n"+
			"[gray]Proto:[::-] [yellow]%s[::-]   [gray]Group:[::-] [yellow]%s[::-]   [gray]Sort:[::-] [yellow]%s[::-]%s",
		up,
		conns,
		humanBytes(rx),
		humanBytes(tx),
		humanRate(rxRate),
		humanRate(txRate),
		m.proto.String(),
		m.group.String(),
		sort,
		extra,
	)
}

func dirArrow(asc bool) string {
	if asc {
		return "↑"
	}
	return "↓"
}

// directionArrow marks a connection row: outgoing (we initiated) shows →,
// incoming (accepted) shows ←, rendered just before the remote address.
func directionArrow(out bool) string {
	if out {
		return "→ "
	}
	return "← "
}

func plainCell(text string) *tview.TableCell {
	return tview.NewTableCell(text).SetAlign(tview.AlignLeft)
}

func rightCell(text string) *tview.TableCell {
	return tview.NewTableCell(text).SetAlign(tview.AlignRight)
}

func colorCell(text string, color tcell.Color, align int) *tview.TableCell {
	return tview.NewTableCell(text).SetAlign(align).SetTextColor(color)
}

func boldCell(text string, color tcell.Color) *tview.TableCell {
	return tview.NewTableCell(text).
		SetAlign(tview.AlignRight).
		SetStyle(tcell.StyleDefault.Bold(true).Foreground(color))
}

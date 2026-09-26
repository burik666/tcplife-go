package main

import (
	"github.com/rivo/tview"
)

// Listed in table-column order; "No grouping" first.
var groupModes = []GroupMode{
	GroupFlat,
	GroupProcess,
	GroupComm,
	GroupRemoteAddr,
	GroupRemoteHost,
	GroupRemotePort,
	GroupLocalAddr,
	GroupLocalHost,
	GroupLocalPort,
}

// Mirrors the table columns (PROTO/STATE have no sort mode); the sum
// variants follow their components.
var sortModes = []SortMode{
	SortTime,
	SortDuration,
	SortPID,
	SortComm,
	SortLaddr,
	SortRaddr,
	SortRX,
	SortTX,
	SortTraffic,
	SortRxRate,
	SortTxRate,
	SortRate,
}

func (m *tui) buildModals() {
	m.groupList = tview.NewList().ShowSecondaryText(false)

	for i, g := range groupModes {
		idx := i

		m.groupList.AddItem(
			g.String(),
			"",
			0,
			func() {
				m.group = groupModes[idx]
				m.collapsed = map[string]bool{}
				m.closeModal()
				m.rebuild()
			},
		)
	}

	m.sortList = tview.NewList().ShowSecondaryText(false)

	for i, s := range sortModes {
		idx := i

		m.sortList.AddItem(
			s.String(),
			"",
			0,
			func() {
				m.sort = sortModes[idx]
				m.closeModal()
				m.rebuild()
			},
		)
	}

	m.groupList.SetDoneFunc(m.closeModal)
	m.sortList.SetDoneFunc(m.closeModal)

	m.pages.AddPage("group", titledBox(m.groupList, " Group by (g) "), true, false)
	m.pages.AddPage("sort", titledBox(m.sortList, " Sort by (s) "), true, false)
}

func (m *tui) openModal(name string) {
	m.modalName = name

	list, idx := m.modalFor(name)
	list.SetCurrentItem(idx)

	m.pages.ShowPage(name)
	m.app.SetFocus(list)
}

// modalFor returns the list backing a modal plus the index of the current
// selection, so openModal can treat both modals uniformly.
func (m *tui) modalFor(name string) (*tview.List, int) {
	if name == "group" {
		return m.groupList, indexOfGroup(m.group)
	}

	return m.sortList, indexOfSort(m.sort)
}

func (m *tui) closeModal() {
	if m.modalName == "" {
		return
	}

	name := m.modalName
	m.modalName = ""

	m.pages.HidePage(name)
	m.pages.ShowPage("main")
	m.app.SetFocus(m.table)
}

func indexOfGroup(g GroupMode) int {
	for i, x := range groupModes {
		if x == g {
			return i
		}
	}
	return 0
}

func indexOfSort(s SortMode) int {
	for i, x := range sortModes {
		if x == s {
			return i
		}
	}
	return 0
}

// titledBox wraps a list in a borderless title and centers it on screen.
func titledBox(list *tview.List, title string) tview.Primitive {
	head := tview.NewTextView().
		SetDynamicColors(true).
		SetTextAlign(tview.AlignCenter).
		SetText("[white::b]" + title + "[::-]")

	box := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(head, 1, 0, false).
		AddItem(list, 0, 1, true)

	list.SetBorder(true).
		SetBorderColor(tview.Styles.SecondaryTextColor)

	return centerBox(box, 44, 14)
}

// centerBox centers a primitive of fixed size within the available area.
func centerBox(item tview.Primitive, width, height int) tview.Primitive {
	return tview.NewFlex().
		AddItem(nil, 0, 1, false).
		AddItem(
			tview.NewFlex().SetDirection(tview.FlexRow).
				AddItem(nil, 0, 1, false).
				AddItem(item, height, 0, false).
				AddItem(nil, 0, 1, false),
			width, 0, true,
		).
		AddItem(nil, 0, 1, false)
}

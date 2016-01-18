package kpstruct

type PasswordGroup struct {
	// TODO
}

type PasswordEntry struct {
	// TODO
}

type GroupHandler func(pg PasswordGroup)
type EntryHandler func(pe PasswordEntry)

func (pg *PasswordGroup) GetCounts(recursive bool) (groups, entries uint32) {
	// TODO
	return 0, 0
}

const (
	GetCountsNonRecursive = false
	GetCountsRecursive = true
)

func (pg *PasswordGroup) TraverseTree(traversalMethod int, gh GroupHandler, eh EntryHandler) {

}

const (
	TraversalMethodPreOrder = iota
)
//go:build linux

package frozt

/*
#cgo LDFLAGS: -L${SRCDIR}/includes/linux -Wl,-rpath,${SRCDIR}/includes/linux -lfroztlib
*/
import "C"

//go:build linux

package frost

/*
#cgo LDFLAGS: -L${SRCDIR}/includes/linux -Wl,-rpath,${SRCDIR}/includes/linux -lfrostlib
*/
import "C"

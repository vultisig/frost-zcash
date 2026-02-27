//go:build darwin

package frost

/*
#cgo LDFLAGS: -L${SRCDIR}/includes/darwin -lfrostlib -Wl,-rpath,${SRCDIR}/includes/darwin
*/
import "C"

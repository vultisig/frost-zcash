//go:build darwin

package frozt

/*
#cgo LDFLAGS: -L${SRCDIR}/includes/darwin -lfroztlib -Wl,-rpath,${SRCDIR}/includes/darwin
*/
import "C"

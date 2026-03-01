//go:build windows

package frozt

/*
#cgo LDFLAGS: -L${SRCDIR}/includes/windows -lfroztlib -lws2_32 -luserenv -lbcrypt -lntdll
*/
import "C"

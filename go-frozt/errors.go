package frozt

import "fmt"

const (
	libOK                = 0
	libInvalidHandle     = 1
	libHandleInUse       = 2
	libInvalidHandleType = 3
	libNullPtr           = 4
	libInvalidBufferSize = 5
	libUnknownError      = 6
	libSerializationErr  = 7
	libInvalidIdentifier = 8
	libDkgError          = 9
	libSigningError      = 10
	libReshareError      = 11
	libKeyImportError    = 12
)

var libErrorMessages = map[int]string{
	libInvalidHandle:     "invalid handle",
	libHandleInUse:       "handle in use",
	libInvalidHandleType: "invalid handle type",
	libNullPtr:           "null pointer",
	libInvalidBufferSize: "invalid buffer size",
	libUnknownError:      "unknown error",
	libSerializationErr:  "serialization error",
	libInvalidIdentifier: "invalid identifier",
	libDkgError:          "dkg error",
	libSigningError:      "signing error",
	libReshareError:      "reshare error",
	libKeyImportError:    "key import error",
}

func mapLibError(code int) error {
	if code == libOK {
		return nil
	}
	msg, found := libErrorMessages[code]
	if found {
		return fmt.Errorf("frozt: %s", msg)
	}
	return fmt.Errorf("frozt: unknown error code %d", code)
}

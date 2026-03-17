package shell

// #cgo CFLAGS: -I/w/rbox-copy/shellsplit/include
// #cgo LDFLAGS: -L/w/rbox-copy/shellsplit -lshellsplit -lm -Wl,-rpath,/w/rbox-copy/shellsplit
// #include <stdlib.h>
// #include "shell_interop.h"
import "C"
import (
	"fmt"
	"unsafe"
)

// Subcommand represents a parsed shell subcommand
type Subcommand struct {
	Index    int
	Type     string
	Features string
	Start    int
	Len      int
	Text     string
}

// ParseCommand parses a shell command and returns subcommands
func ParseCommand(cmd string) ([]Subcommand, error) {
	if cmd == "" {
		return nil, nil
	}

	cCmd := C.CString(cmd)
	defer C.free(unsafe.Pointer(cCmd))

	count := C.shell_interop_parse(cCmd, C.int(len(cmd)))
	if count <= 0 {
		return nil, fmt.Errorf("parse failed")
	}

	subcommands := make([]Subcommand, int(count))
	for i := 0; i < int(count); i++ {
		cIdx := C.int(i)

		// Get type
		cType := C.shell_interop_subcommand_type(cIdx)
		cTypeStr := C.shell_interop_type_str(cType)
		defer C.shell_interop_free_str(cTypeStr)
		typeStr := C.GoString(cTypeStr)

		// Get features
		cFeatures := C.shell_interop_subcommand_features(cIdx)
		cFeaturesStr := C.shell_interop_features_str(cFeatures)
		defer C.shell_interop_free_str(cFeaturesStr)
		featuresStr := C.GoString(cFeaturesStr)

		// Get position
		start := int(C.shell_interop_subcommand_start(cIdx))
		length := int(C.shell_interop_subcommand_len(cIdx))

		// Get text
		cText := C.shell_interop_subcommand_str(cIdx)
		defer C.shell_interop_free_str(cText)
		textStr := C.GoString(cText)

		subcommands[i] = Subcommand{
			Index:    i,
			Type:     typeStr,
			Features: featuresStr,
			Start:    start,
			Len:      length,
			Text:     textStr,
		}
	}

	return subcommands, nil
}

// ParseCommandToString returns a simple string representation
func ParseCommandToString(cmd string) string {
	subcommands, err := ParseCommand(cmd)
	if err != nil || subcommands == nil {
		return ""
	}

	result := ""
	for i, sc := range subcommands {
		if i > 0 {
			result += " | "
		}
		result += fmt.Sprintf("[%s:%s]", sc.Type, sc.Features)
	}
	return result
}

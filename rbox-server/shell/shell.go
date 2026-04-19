package shell

// #cgo CFLAGS: -I../../shellgate/include -I../../shellsplit/include -I../../shelltype/include
// #cgo LDFLAGS: -L../../shellgate/build -lshellgate -lshelltype_gate -lshellsplit_gate -lm
// #include <shellgate.h>
// #include <stdlib.h>
// #include <string.h>
import "C"
import (
	"fmt"
	"runtime"
	"unsafe"
)

type Verdict int

const (
	VerdictAllow   Verdict = 0
	VerdictDeny    Verdict = 1
	VerdictReject  Verdict = 2
)

type SubcmdResult struct {
	Matches      bool
	Verdict      Verdict
	Command      string
	RejectReason string
	WriteCount   uint32
	ReadCount    uint32
	EnvCount     uint32
	Violations   uint32
}

type Violation struct {
	Type        uint32
	Severity    uint32
	Description string
	Detail      string
}

type EvalResult struct {
	Verdict      Verdict
	DenyReason   string
	Subcmds      []SubcmdResult
	Suggestions  []string
	Violations   []Violation
	HasViolation bool
	ViolFlags    uint32
	Truncated    bool
}

type Gate struct {
	gate *C.sg_gate_t
	buf  []byte
}

func NewGate() (*Gate, error) {
	g := C.sg_gate_new()
	if g == nil {
		return nil, fmt.Errorf("sg_gate_new failed")
	}

	cfg := (*C.sg_violation_config_t)(C.malloc(C.size_t(unsafe.Sizeof(C.sg_violation_config_t{}))))
	if cfg != nil {
		C.sg_violation_config_default(cfg)
		C.sg_gate_set_violation_config(g, cfg)
		C.free(unsafe.Pointer(cfg))
	}

	C.sg_gate_set_suggestions(g, C.bool(true))

	gate := &Gate{
		gate: g,
		buf:  make([]byte, 8192),
	}
	runtime.SetFinalizer(gate, (*Gate).Close)
	return gate, nil
}

func (g *Gate) Close() {
	if g.gate != nil {
		C.sg_gate_free(g.gate)
		g.gate = nil
	}
	runtime.SetFinalizer(g, nil)
}

func (g *Gate) Eval(cmd string) (*EvalResult, error) {
	if cmd == "" || g.gate == nil {
		return nil, nil
	}

	cCmd := C.CString(cmd)
	defer C.free(unsafe.Pointer(cCmd))

	var out C.sg_result_t
	rc := C.sg_eval(
		g.gate,
		cCmd,
		(*C.char)(unsafe.Pointer(&g.buf[0])),
		C.size_t(len(g.buf)),
		&out,
	)

	if rc == C.SG_ERR_INVALID {
		return nil, fmt.Errorf("invalid arguments")
	}

	result := &EvalResult{
		Verdict:      verdictFromC(out.verdict),
		DenyReason:   cStr(out.deny_reason),
		HasViolation: bool(out.has_violations),
		ViolFlags:    uint32(out.violation_flags),
		Truncated:    bool(out.truncated),
	}

	for i := uint32(0); i < uint32(out.subcmd_count); i++ {
		sc := out.subcmds[i]
		result.Subcmds = append(result.Subcmds, SubcmdResult{
			Matches:      bool(sc.matches),
			Verdict:      verdictFromC(sc.verdict),
			Command:      cStr(sc.command),
			RejectReason: cStr(sc.reject_reason),
			WriteCount:   uint32(sc.write_count),
			ReadCount:    uint32(sc.read_count),
			EnvCount:     uint32(sc.env_count),
			Violations:   uint32(sc.violation_flags),
		})
	}

	for i := uint32(0); i < uint32(out.suggestion_count); i++ {
		if s := cStr(out.suggestions[i]); s != "" {
			result.Suggestions = append(result.Suggestions, s)
		}
	}

	for i := uint32(0); i < uint32(out.violation_count); i++ {
		v := out.violations[i]
		result.Violations = append(result.Violations, Violation{
			Type:        uint32(v._type),
			Severity:    uint32(v.severity),
			Description: cStr(v.description),
			Detail:      cStr(v.detail),
		})
	}

	return result, nil
}

func (g *Gate) AddRule(pattern string) error {
	if g.gate == nil {
		return fmt.Errorf("gate is nil")
	}
	cPat := C.CString(pattern)
	defer C.free(unsafe.Pointer(cPat))
	rc := C.sg_gate_add_rule(g.gate, cPat)
	if rc != C.SG_OK {
		return fmt.Errorf("add rule failed: %d", int(rc))
	}
	return nil
}

func (g *Gate) RemoveRule(pattern string) error {
	if g.gate == nil {
		return fmt.Errorf("gate is nil")
	}
	cPat := C.CString(pattern)
	defer C.free(unsafe.Pointer(cPat))
	C.sg_gate_remove_rule(g.gate, cPat)
	return nil
}

func (g *Gate) RuleCount() uint32 {
	if g.gate == nil {
		return 0
	}
	return uint32(C.sg_gate_rule_count(g.gate))
}

func (g *Gate) SavePolicy(path string) error {
	if g.gate == nil {
		return fmt.Errorf("gate is nil")
	}
	cPath := C.CString(path)
	defer C.free(unsafe.Pointer(cPath))
	rc := C.sg_gate_save_policy(g.gate, cPath)
	if rc != C.SG_OK {
		return fmt.Errorf("save policy failed: %d", int(rc))
	}
	return nil
}

func (g *Gate) LoadPolicy(path string) error {
	if g.gate == nil {
		return fmt.Errorf("gate is nil")
	}
	cPath := C.CString(path)
	defer C.free(unsafe.Pointer(cPath))
	rc := C.sg_gate_load_policy(g.gate, cPath)
	if rc != C.SG_OK {
		return fmt.Errorf("load policy failed: %d", int(rc))
	}
	return nil
}

func (g *Gate) SetCWD(cwd string) error {
	if g.gate == nil {
		return fmt.Errorf("gate is nil")
	}
	cCwd := C.CString(cwd)
	defer C.free(unsafe.Pointer(cCwd))
	rc := C.sg_gate_set_cwd(g.gate, cCwd)
	if rc != C.SG_OK {
		return fmt.Errorf("set cwd failed: %d", int(rc))
	}
	return nil
}

func VerdictName(v Verdict) string {
	switch v {
	case VerdictAllow:
		return "ALLOW"
	case VerdictDeny:
		return "DENY"
	case VerdictReject:
		return "REJECT"
	default:
		return "UNKNOWN"
	}
}

func ViolationCategoryName(flags uint32) string {
	const (
		catFilesystem = uint32(C.SG_VIOL_CAT_FILESYSTEM)
		catPrivilege  = uint32(C.SG_VIOL_CAT_PRIVILEGE)
		catExfil      = uint32(C.SG_VIOL_CAT_EXFIL)
		catNetwork    = uint32(C.SG_VIOL_CAT_NETWORK)
	)
	if flags&catFilesystem != 0 {
		return "filesystem"
	}
	if flags&catPrivilege != 0 {
		return "privilege"
	}
	if flags&catExfil != 0 {
		return "exfiltration"
	}
	if flags&catNetwork != 0 {
		return "network"
	}
	return "unknown"
}

func verdictFromC(v C.sg_verdict_t) Verdict {
	switch v {
	case C.SG_VERDICT_ALLOW:
		return VerdictAllow
	case C.SG_VERDICT_DENY:
		return VerdictDeny
	case C.SG_VERDICT_REJECT:
		return VerdictReject
	default:
		return VerdictAllow
	}
}

func cStr(s *C.char) string {
	if s == nil {
		return ""
	}
	return C.GoString(s)
}

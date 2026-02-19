# C-DFA Documentation

This directory contains all design and implementation documentation for the C-DFA project.

## Directory Structure

### design/
Architecture and design decisions:
- **ARCHITECTURE.md** - Overall system architecture
- **CONTROL_STRUCTURES.md** - Control flow design
- **DFA_IMPROVEMENTS.md** - Planned and implemented improvements
- **PATTERN_SYSTEM.md** - Pattern syntax and semantics
- **SAT_ENCODING_DESIGN.md** - SAT-based minimization design
- **TRANSFORMATION_ARCHITECTURE.md** - NFA-to-DFA transformation design

### implementation/
Implementation details and guides:
- **LAYOUT_OPTIMIZATION.md** - State layout optimization
- **NFA_PREMINIMIZATION.md** - Pre-minimization optimization
- **PATTERN_ORDERING.md** - Pattern ordering for efficiency
- **SAT_ENCODING_IMPLEMENTATION.md** - SAT solver integration
- **TEST_ORGANIZATION.md** - Testing strategy
- **TRANSITION_COMPRESSION.md** - Rule compression techniques

### notes/
Developer notes and less formal documentation:
- **CaptureNotes.md** - Capture group implementation notes
- **DFANotes.md** - DFA implementation notes
- **DFASystemNotes.md** - System-level notes
- **FAILURE_HANDLING.md** - Error handling strategy
- **OPTIMIZATION_ANALYSIS.md** - Performance analysis
- **PIPELINE_HANDLING.md** - Pipeline processing notes
- **SHELL_*.md** - Shell integration documentation
- **TaggedDFA*.md** - Tagged DFA implementation notes
- **UNDER_THE_HOOD.md** - Internal workings guide

## Quick Start

For new contributors:
1. Start with `design/ARCHITECTURE.md` for system overview
2. Read `notes/UNDER_THE_HOOD.md` for implementation details
3. Check `implementation/TEST_ORGANIZATION.md` for testing guide

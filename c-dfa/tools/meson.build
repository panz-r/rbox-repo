# DFA Builder Tools

# Advanced NFA builder with termination tags
nfa_builder = executable('nfa_builder',
  'nfa_builder.c',
  include_directories: [
    include_directories('../include'),
    include_directories('../src')
  ],
  install: false)

# NFA to DFA converter
nfa2dfa = executable('nfa2dfa',
  'nfa2dfa.c',
  include_directories: [
    include_directories('../include'),
    include_directories('../src')
  ],
  install: false)

# DFA serializer
 dfaser = executable('dfaser',
  'dfaser.c',
  include_directories: [
    include_directories('../include'),
    include_directories('../src')
  ],
  install: false)

# DFA visualizer (for debugging)
dfaviz = executable('dfaviz',
  'dfaviz.c',
  include_directories: [
    include_directories('../include'),
    include_directories('../src')
  ],
  install: false)

# Custom target to build DFA from specification
custom_target('build-dfa',
  input: ['commands.txt'],
  output: ['readonlybox.dfa'],
  command: [nfa2dfa, '@INPUT@', '@OUTPUT@'],
  depends: nfa2dfa,
  build_by_default: true,
  install: false)
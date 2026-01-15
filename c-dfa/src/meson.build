# DFA Library
install_dir = get_option('prefix') / 'include' / 'readonlybox-dfa'

libdfa = library('dfa',
  sources: [
    'dfa_eval.c',
    'dfa_loader.c',
    'shell_tokenizer.c',
    'shell_processor.c',
    'shell_tokenizer_ext.c',
    'shell_transform.c',
    'readonlybox.c'
  ],
  include_directories: [
    include_directories('.'),
    include_directories('../include')
  ],
  install: true,
  install_dir: install_dir)

# Install headers
install_headers(
  '../include/dfa.h',
  '../include/dfa_types.h',
  '../include/dfa_compact.h',
  '../include/shell_tokenizer.h',
  '../include/shell_processor.h',
  '../include/shell_tokenizer_ext.h',
  '../include/shell_transform.h',
  '../include/readonlybox.h',
  subdir: 'readonlybox-dfa')

# Test executable
executable('dfa_test',
  'dfa_test.c',
  link_with: libdfa,
  include_directories: include_directories('../include'))

# Benchmark executable
executable('dfa_bench',
  'dfa_bench.c',
  link_with: libdfa,
  include_directories: include_directories('../include'))

# Tokenizer test executable
executable('tokenizer_test',
  'tokenizer_test.c',
  link_with: libdfa,
  include_directories: include_directories('../include'))

# Comprehensive test executable
executable('comprehensive_test',
  'comprehensive_test.c',
  link_with: libdfa,
  include_directories: include_directories('../include'))

# Specific example test
executable('specific_test',
  'specific_test.c',
  link_with: libdfa,
  include_directories: include_directories('../include'))

# Separation test
executable('separation_test',
  'separation_test.c',
  link_with: libdfa,
  include_directories: include_directories('../include'))

# Extended tokenizer test
executable('extended_test',
  'extended_test.c',
  link_with: libdfa,
  include_directories: include_directories('../include'))

# Transformation test
executable('transform_test',
  'transform_test.c',
  link_with: libdfa,
  include_directories: include_directories('../include'))

# Pipeline test
executable('pipeline_test',
  'pipeline_test.c',
  link_with: libdfa,
  include_directories: include_directories('../include'))
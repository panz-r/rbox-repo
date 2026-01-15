project('readonlybox-dfa', 'c',
  version: '0.1.0',
  default_options: ['warning_level=3', 'c_std=c11'])

# Subdirectories
subdir('src')
subdir('tools')

# Configuration
dfa_data_dir = join_paths(meson.current_source_dir(), 'data')
build_dir = join_paths(meson.current_build_dir(), 'dfa')

# Make sure build directory exists
run_command('mkdir', '-p', build_dir)

# Install headers
install_dir = get_option('prefix') / 'include' / 'readonlybox-dfa'

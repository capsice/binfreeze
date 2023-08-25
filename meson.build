# yes I'm using meson for this even though a makefile would have been less than half the size

project(
	'binfreeze', 
	'c', 
	default_options: [
		'c_std=c11',
		'warning_level=2',
		'werror=true',
	],
	version: '0.1.0'
)

project_name = meson.project_name()

configure_file(
    input: 'include/config.h.in',
    output: 'config.h',
    configuration: {
			'VERSION': meson.project_version(), 
			'NAME': project_name
		},
)

add_global_arguments(
	[
		'-Wunused-result',
		'-Wno-unused-parameter',
		'-Wno-unused-result',
		'-Wno-missing-braces',
		'-Wno-format-zero-length',
		'-Wunused-result',
		'-Wundef',
		'-Wvla',
	],
	language: 'c',
)

meson.add_install_script('scripts/populate_config.sh')

executable(
	project_name,
	files('src/main.c', 'src/rules.c'),
	include_directories: include_directories('include'),
	install : true
)
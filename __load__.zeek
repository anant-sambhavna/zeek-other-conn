##! Package root loader. zkg uses script_dir=scripts, but this lets the
##! package also be loaded by directory name (e.g. in tests or via a plain
##! ZEEKPATH entry).

@load ./scripts

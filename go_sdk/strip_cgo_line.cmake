# Generates liblattigo_sanitized.h from liblattigo.h by replacing cgo #line directives
# that reference virtual filenames (e.g. "cgo-builtin-export-prolog") with blank lines.
# These virtual names are not real files; NVCC's -MD dep scanner emits them as Make
# prerequisites, causing all .cu files to be considered always-stale.
# GCC/Clang are unaffected (their dep scanners ignore #line arguments), but using the
# sanitized header universally avoids any future toolchain hitting the same issue.
set(SRC "${CMAKE_CURRENT_LIST_DIR}/liblattigo.h")
set(DST "${CMAKE_CURRENT_LIST_DIR}/liblattigo_sanitized.h")

file(READ "${SRC}" content)
# Replace: #line <N> "cgo-<anything>"   →   (empty line)
string(REGEX REPLACE "#line [0-9]+ \"cgo-[^\"\n]*\"" "" content "${content}")
file(WRITE "${DST}" "${content}")

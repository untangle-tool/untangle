# Title - TBD

The purpose of this tool is to find calls to function pointers inside the
functions a library, and to find the values of global variables and parameters
that are needed to get to the function pointer call.

## Requirements

* CodeQL: install following instructions here: https://codeql.github.com/docs/codeql-cli/getting-started-with-the-codeql-cli/
* `angr`: install following instructions here: https://docs.angr.io/installation/
* Python >= 3.7 (PyPy recommended)
* Python modules listed in `requirements.txt`, intallable through
  `pip install -r requirements.txt`

## Usage

First of all, prepare the library you want to analyze:

1. Obtain a copy of the source code of the library to analyze.

2. Configure the library to make it ready for building as needed
   (e.g. `autoreconf`, `./configure` script, etc).

3. Generate the CodeQL database and extract useful information (function
   pointers, types) from the library. You will need to provide the build command
   for the library (e.g. `make -j`) as command-line argument:

    ```bash
    python3 -m symex_tool.main build libfoo_source libfoo_build libfoo_db "lib_build_command"
    ```

   This will create and build an instrumented modified copy of the library
   (`libfoo_source`) in the directory `libfoo_build` as well as the CodeQL DB in
   `libfoo_db`.

   **Note**: due to the nature of the instrumentation, compilation of the
   instrumented library might fail because the linker may find the same
   `SYMEX_...` symbol defined multiple times. If that's the case, you need to
   pass `-z,muldefs` to the linker: how to do this depends on the library you
   are building. Sometimes it's enough to just `export LDFLAGS=Wl,-z,muldefs`
   before building as it will get picked up by `make`.

Using the `list` command you can list all function pointers found (if any) along
with the location of their calls and the library function through which such
locations may be reachable:

```bash
python3 -m symex_tool.main list libfoo_build libfoo_db
```

Using the `exec` command you can start symbolic execution of all interesting
library functions found in the library, trying to reach ***any*** function pointer
call:

```bash
python3 -m symex_tool.main exec libfoo_build libfoo_db libfoo_build/path/to/libname.so output_dir
```

Using the `exec-filter` command you can also filter by library function name,
function pointer name, or exact location (this information is taken from the
`list` command):

```bash
python3 -m symex_tool.main exec-filter --functoin 'foo_[a-z]+' --fptr 'foo_hook_(one|two)' ...
python3 -m symex_tool.main exec-filter --loc 'src/foo.c:123:10:123:20' ...
```

You can also try to automatically verify the correctness of the results by
passing `--verify` to either `exec` or `exec-filter`.

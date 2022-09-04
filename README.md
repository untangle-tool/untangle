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

To use the tool, you need to follow these steps:

1. Obtain a copy of the source code of the library to analyze.

2. Configure the library to make it ready for building as needed
   (e.g. `autoreconf`, `./configure` script, etc).

3. Generate the CodeQL database and extract useful information (function
   pointers, types) from the library. You will need to provide the build command
   for the library (e.g. `make -j`) as command-line argument:

    ```bash
    python3 -m symex_tool.main build libfoo_source libfoo_db "lib_build_command"
    ```

    This will create and build a modified copy of the library in a new directory
    (e.g. `libfoo_build`).

4. Start symbolic execution on the newly built library copy:

    ```bash
    python3 -m symex_tool.main exec libfoo_build libfoo_db libfoo_build/path/to/libname.so libfoo_output
    ```

    The output will be in the specified `libfoo_output`.

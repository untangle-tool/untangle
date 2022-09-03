# Title - TBD

The purpose of this tool is to find calls to function pointers inside the
functions a library, and to find the values of global variables and parameters
that are needed to get to the function pointer call.

## Structure of the tool

The tool is composed of three parts:

1. A script that relies on CodeQL to find the function pointers in the library.
2. A script that modifies the code to replace the function pointers with a call
   to a fictitious function called "TARGETFUNC".
3. A script that uses angr to perform the symbolic execution of the functions
   found with the first script and produce a report of the values of the
   parameters and global variables that are needed to get to the function
   pointer call.

The directories will be organized as follows:

* The output of the script will be placed in the `output_dir` folder
* One folder will be created for each library that will be analyzed.
* One file will be created for each function that will be symbolically executed.

## Requirements

* CodeQL: install following instructions here: https://codeql.github.com/docs/codeql-cli/getting-started-with-the-codeql-cli/
* Python 3.10
* angr: install following instructions here: https://docs.angr.io/installation/
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

4. Run the analysis on the newly built library copy:

    ```bash
    python3 -m symex_tool.main analyze libfoo_build libfoo_db libfoo_build/path/to/libname.so libfoo_output
    ```

    The output will be in the specified `libfoo_output`.

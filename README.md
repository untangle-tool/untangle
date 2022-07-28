# Title - TBD
The purpose of this tool is to find calls to function pointers inside the functions a library, and to find the values of global variables and parameters that are needed to get to the function pointer call.

## Structure of the tool
The tool is composed of three parts:
1. A script that relies on CodeQL to find the function pointers in the library.
2. A script that modifies the code to replace the function pointers with a call to a fictitious function called "TARGETFUNC".
3. A script that uses angr to perform the symbolic execution of the functions found with the first script and produce a report of the values of the parameters and global variables that are needed to get to the function pointer call.

The directories will be organized as follows:
* The output of the script will be placed in the `output_dir` folder
* One folder will be created for each library that will be analyzed.
* One file will be created for each function that will be symbolically executed.

## Requirements
* CodeQL: install following instructions here https://codeql.github.com/docs/codeql-cli/getting-started-with-the-codeql-cli/
* Python 3.10
* angr: install following instructions here https://docs.angr.io/installation/

## Usage
To run the tool, you need to follow these steps:
1. Generate the CodeQL database for the library (see below) and run the script to find function pointers, saving the output in a file:
    ```bash
    ./find_func_ptrs.py lib-db > out_file
    ```
2. Run the script to modify the source code of the libraries, inserting calls to TARGETFUNC instead of function pointers:
    ```bash
    ./replace_calls.py lib_src_folder out_file
    ```
3. Recompile the needed libraries
4. Run the script to symbolically execute the functions and produce a file for each one.
    ```bash
    ./main.py -i out_file lib_bin_name [-i out_file lib_bin_name ...]
    ```
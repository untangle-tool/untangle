# SymEx Tool
## Goal
Build a binary analysis framework that, given some parameters in input (library file, function name, name and size of the parameters and name of a target function to reach), creates a C file that links the library and calls the exported function.
Then, it should compile the file and run it with angr, with the objective to get to the call to "TARGET".

The objective is to understand which parameters we should pass to the function to redirect the control flow to the function call.

## Implementation
I plan to use `argparse` to parse the command line arguments: it's pretty simple and intuitive, and it allows to easily write a help documentation.

The name of the C file will be stored in a global variable, at least for the moment.

## Instructions
First, compile the static library:
```
gcc -c lib.c
ar -rc lib.a *.o
```
Then, start the script by passing the following arguments:
* library name (without extension)
* name of the function containing the vulnerable function pointer call
* name of the target call to reach with angr
* \[Optional\] function parameters, in the form `-p param_name param_type param_size`

The type of the parameter is needed to declare it in the created C file (cannot infer the file type only from the size).
To print the help message, simply run the script with the -h flag set:
```
$ python main.py -h
usage: main.py [-h] [-p param_name param_type param_size] library_name function_name target_fn_name

Symbolic Execution tool to find the values that need to be passed to parameters to get to a vulnerable function call.

positional arguments:
  library_name          Name of the library containing the function.
  function_name         Name of the function containing the vulnerable function call.
  target_fn_name        Name of the target function to be reached through symbolical execution.

optional arguments:
  -h, --help            show this help message and exit
  -p param_name param_type param_size, --parameter param_name param_type param_size
                        Name, type and size of the parameter(s) of the function. Pointers should be specified with type 'ptr'.
```

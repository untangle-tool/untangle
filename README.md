# SymEx project
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
# Title - TBD
The purpose of this tool is to find calls to function pointers inside the functions a library, and to find the values of global variables and parameters that are needed to get to the function pointer call.

The tool is composed of two parts:
1. A script that relies on CodeQL to find the function pointers in the library.
2. A script that uses angr to perform the symbolic execution of the functions found with the first script and produce a report of the values of the parameters and global variables that are needed to get to the function pointer call.

## Requirements
* CodeQL: install following instructions here https://codeql.github.com/docs/codeql-cli/getting-started-with-the-codeql-cli/
* Python 3.10
* angr: install following instructions here https://docs.angr.io/installation/

## Function pointers finder
Create a database for a library:

- Get source of the library and read the readme/build/install info files
- Install needed build dependencies
- Configure the library how you want (usually using `./configure --help` to see
  the options)
- Find the command needed to build the whole thing (most probably `make` or
  similar), for make use `-j` to use all cores.
- Run it with `codeql`:

		codeql database create path/to/output/db --language=cpp --command 'COMMAND-TO-BUILD-LIB'

  (codeql does not differentiate C and C++)

For example for libcurl:

```bash
git clone 'https://github.com/curl/curl'
cd curl
./configure --disable-static --with-openssl --without-brotli --disable-static
codeql database create ../curl-db --language=cpp --command 'make -j'
```

Then point my script to the db you created:

```
./find_func_ptrs.py curl-db
```

You will see an output like this:

```
Curl_cfree declared at lib/easy.c:115
        called from Curl_cookie_init at lib/cookie.c:1225:5:1225:14
                reachable from Curl_cookie_loadfiles defined at lib/cookie.c:328
                reachable from Curl_cookie_init defined at lib/cookie.c:1157
...
```

Meaning that:

- `Curl_cfree` is the global function pointer
- `Curl_cookie_init` calls it somehow
- `Curl_cookie_init` is somehow reachable from `Curl_cookie_loadfiles` and
  `Curl_cookie_init` through a chain of calls

What you are interested in for testing is replacing the bit of source code at
"called from ...", which can be automated something like this:

```python
# called from Curl_cookie_init at lib/cookie.c:1225:5:1225:14

fname = 'lib/cookie.c'
start_line, start_col, end_line, end_col = 1225, 5, 1225, 14

with open(fname, 'r') as f:
	source = f.readlines()

source.insert(0, 'void TARGETFUNC(void) {}\n')
source[start_line] = source[start_line].replace('Curl_cfree', 'TARGETFUNC')
# this is the "stupid" way to do it, you could also use the start and end column
# info to be more precise

with open('libtarget.c', 'w') as f:
	for line in source:
		f.write(line)
```

Now clean the build (usually `make clean` or `make distclean`) and rebuild the
library with the modified source code, after which you should be able to run it
in your tool.


## Symbolic execution part
First, place the library in the `libs` folder.

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

To speed up the process and avoid writing long commands every time, `start_script.sh` is provided.

The output of the script will be something like this:
```
$ ./start_script.sh                                                                              
<--- Function arguments --->
*       a = b'4338770\xb2'
*       b = b'\x00'
<--- Global variables --->
*       Global found at offset 0x4020 (section .bss) with size 4
*       Value of the global should be: b'\xff\x0f\x00\x00'
*       Global found at offset 0x4024 (section .bss) with size 4
*       Value of the global should be: b'\xef\xbe\xad\xde'
```
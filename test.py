import angr

C_FILE_NAME = "temp"

proj = angr.Project(f'./{C_FILE_NAME}')
target = 'exported_func4'
target_sym = proj.loader.find_symbol(target)
print(target_sym)

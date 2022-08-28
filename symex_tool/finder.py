import logging
from collections import defaultdict

from .codeql import run_codeql_query

logger = logging.getLogger('finder')

def find_function_pointers(codeql_db_path):
    logger.debug('Extracting global function pointers from CodeQL DB "%s"', codeql_db_path)
    results = run_codeql_query(codeql_db_path, FUNC_PTRS_QUERY)

    fptr_decls = {}
    fptr_calls = defaultdict(lambda: defaultdict(list))

    for name, typ, decl_loc, *call_loc, exported_func, exported_loc, sig in results:
        fptr_decls[name] = decl_loc
        fptr_calls[name][tuple(call_loc)].append((exported_func, exported_loc, sig))

    # {func_ptr_name: {call_loc: [(exported_func, signature), ...]}}
    res = defaultdict(lambda: defaultdict(list))

    for name, decl_loc in fptr_decls.items():
        # print(name, 'declared at', decl_loc)
        calls = fptr_calls[name]

        for call_loc in calls:
            caller, *loc = call_loc
            loc = tuple(loc)
            # print('\tcalled from', caller, 'at', ':'.join(loc))

            for exp_func, exp_loc, sig in calls[call_loc]:
                # print('\t\treachable from', exp_func, 'defined at', exp_loc, 'with signature', sig)
                res[name][loc].append((exp_func, sig))

    return res

################################################################################


FUNC_PTRS_QUERY = '''
import cpp

class FancyFunc extends Function {
    predicate isExported() {
        not this.isStatic()
    }

    FancyFunc getACaller() {
        result = this.getACallToThisFunction().getEnclosingFunction()
    }

    FancyFunc getARootExportedFunc() {
        result = this.getACaller*() and result.isExported()
    }

    private string stringifyParam(Parameter p) {
        if p.getUnderlyingType() instanceof Enum
        then result = "int" // NOTE: C++11 enums may have different enum-base
        else result = p.getUnderlyingType().getUnspecifiedType().toString()
    }

    private string sig(Parameter cur, int nLeft) {
        if nLeft = 0
        then result = this.stringifyParam(cur)
        else result = (this.stringifyParam(cur) + ", "
            + this.sig(this.getParameter(this.getNumberOfParameters() - nLeft), nLeft - 1))
    }

    string getSimplifiedSignature() {
        (this.getNumberOfParameters() = 0 and result = "void")
        or
        result = this.sig(this.getParameter(0), this.getNumberOfParameters() - 1)
    }
}

from
    GlobalVariable v,
    Type t,
    FunctionPointerIshType f,
    VariableCall vc,
    VariableAccess va,
    Location l,
    FancyFunc leaf,
    FancyFunc root
where
    not v.isConst()
    and t = v.getType()
    and (f = t or f = t.getUnderlyingType())
    and va = vc.getExpr()
    and v = va.getTarget()
    and l = va.getLocation()
    and leaf = va.getEnclosingFunction()
    and root = leaf.getARootExportedFunc()
select
    v as Variable,
    t as Type,
    v.getLocation().getFile().getRelativePath() + ":" + v.getLocation().getStartLine() as DeclLocation,
    leaf.getQualifiedName() as CallerFunc,
    l.getFile().getRelativePath() as CallFile,
    l.getStartLine() as CallStartRow,
    l.getStartColumn() as CallStartCol,
    l.getEndLine() as CallEndRow,
    l.getEndColumn() as CallEndCol,
    root.getQualifiedName() as ExportedFunc,
    root.getLocation().getFile().getRelativePath() + ":" + root.getLocation().getStartLine() as Location,
    root.getSimplifiedSignature() as Signature
'''

if __name__ == '__main__':
    main(sys.argv)

import logging
from typing import List, Dict
from collections import deque

from .variables import Struct, StructField, Variable, StructPointer


logger = logging.getLogger('parser')


def parse_signature(signature: str, structs: dict) -> List[Variable]:
    res = []
    signature = signature.split(', ')

    for i, param in enumerate(signature):
        if param[-1] == ']':
            # Turn `type[n]` into `type *`
            param = param[:param.rfind('[')] + ' *'

        typ = param.replace('*', '').strip()

        if param == 'void':
            assert len(signature) == 1
            return []

        if typ in SCALARS:
            size = SCALARS[typ]
            res.append(Variable(f'param_{i}', typ, size))
        else:
            if param.count('*') == 1 and typ in structs:
                p = parse_struct_ptr(f'param_{i}', typ, structs)
                if p is None:
                    logger.warning('Unknown type %r', typ)

                res.append(p)
                continue

            if '*' in param:
                typ = '*'
                size = 8
            else:
                size = SCALARS[typ]

            res.append(Variable(f'param_{i}', typ, size))

    assert len(res) == len(signature), f'{signature!r}\n{res!r}'
    return res


def parse_struct_ptr(name: str, struct_name: str, structs: Dict[str,Struct]) -> StructPointer:
    if struct_name not in structs:
        return None

    logger.debug('Recursively parsing struct %r', struct_name)
    root = StructPointer(struct_name, name, name, structs[struct_name].size, {})
    q = deque([root])
    parent_struct = {}

    while q:
        cur = q.popleft()

        for f in structs[cur.struct_name].fields:
            # Cannot parse these further
            if f.type in ('struct <unnamed>', 'union <unnamed>'):
                cur.fields[f.offset] = (f.name, f.size)
                continue

            fname, ftype, foff, fsize = f
            array_sz = 1

            # Detect array members
            if ftype.endswith(']'):
                start = ftype.rfind('[')
                array_sz = int(ftype[start + 1:-1])

                if array_sz == 0:
                    # Flexible array member, can't handle these
                    cur.fields[f.offset] = (f.name, f.size)
                    continue

                ftype = ftype[:start]
                fsize //= array_sz

            if ftype.endswith('*'):
                ftype = ftype[:-1].strip()

                # Cannot handle double pointers
                if not ftype.endswith('*'):
                    # Another struct pointer?
                    if ftype not in PRIMITIVE_TYPES:
                        inf = False

                        # Avoid infinite loops
                        if ftype == cur.struct_name:
                            inf = True
                        else:
                            par = ftype
                            seen = set(par)

                            while par in parent_struct:
                                newpar = parent_struct[par]
                                if newpar == ftype or newpar in seen:
                                    inf = True
                                    break

                                if newpar == par:
                                    break

                                par = newpar
                                seen.add(par)

                        if not inf:
                            parent_struct[ftype] = cur.struct_name

                            for i in range(array_sz):
                                if ftype in structs:
                                    ptr_name = fname + f'[{i}]' if array_sz > 1 else fname
                                    full_name = f'{cur.full_name}->{ptr_name}'
                                    p = StructPointer(ftype, ptr_name, full_name, structs[ftype].size, {})
                                    cur.fields[foff + i * fsize] = p
                                    q.append(p)

                            continue

            # A "normal" field or a ptr to a struct that we don't know about
            for i in range(array_sz):
                ptr_name = fname + f'[{i}]' if array_sz > 1 else fname
                cur.fields[foff + i * fsize] = (ptr_name, fsize)

    return root


################################################################################


SCALARS = {
    'bool'              : 1,
    'char'              : 1,
    'signed char'       : 1,
    'unsigned char'     : 1,
    'short'             : 2,
    'signed short'      : 2,
    'unsigned short'    : 2,
    'int'               : 4,
    'signed int'        : 4,
    'unsigned int'      : 4,
    'long'              : 8,
    'signed long'       : 8,
    'unsigned long'     : 8,
    'long long'         : 8,
    'signed long long'  : 8,
    'unsigned long long': 8,
    'float'             : 4,
    'double'            : 8,
    'long double'       : 16,
    '(unnamed enum)'    : 4,
}

PRIMITIVE_TYPES = {
    'float',
    'double',
    'long double',
    'bool',
    '(unnamed enum)',
    '..(*)(..)',
    'void'
}

INTS = [
    'char',
    'short',
    'int',
    'long',
    'long long',
]

for t in INTS:
    PRIMITIVE_TYPES.add(t)
    PRIMITIVE_TYPES.add(t + ' *')
    PRIMITIVE_TYPES.add('signed ' + t)
    PRIMITIVE_TYPES.add('signed ' + t + ' *')
    PRIMITIVE_TYPES.add('unsigned ' + t)
    PRIMITIVE_TYPES.add('unsigned ' + t + ' *')

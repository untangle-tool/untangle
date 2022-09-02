import angr
import claripy
import logging
from copy import deepcopy
from typing import Dict, Iterable
from angr.storage.memory_mixins import DefaultMemory


from .variable import Variable, Pointer

logger = logging.getLogger('memory')


class CustomMemory(DefaultMemory):
    alloc_base: int
    tracked   : list[Pointer]

    def __init__(self, *a, **kwa):
        self.alloc_base = 0xf00f000000000000
        self.__init_tracked(kwa.pop('tracked_ptrs', None))
        self.__init_from_project(kwa.pop('project', None), *a, **kwa)

    def __init_from_project(self, project: angr.Project, *a, **kwa):
        assert project is not None

        pmap = {}
        for obj in project.loader.all_objects:
            for seg in obj.segments:
                perms = 1 * seg.is_readable | 2 * seg.is_writable | 4 * seg.is_executable
                pmap[(seg.min_addr, seg.max_addr)] = perms

        super().__init__(
            *a,
            cle_memory_backer= project.loader,
            dict_memory_backer= None,
            stack_size= 8388608,
            stack_end= 576460752303357952,
            stack_perms= 7 if project.loader.main_object.execstack else 3,
            permissions_map= pmap,
            default_permissions= 3,
            **kwa
        )

    def __init_tracked(self, lst: Iterable[Pointer]):
        assert lst is not None

        self.tracked = []
        for t in lst:
            self.tracked += t.flatten()

    def __allocate_object(self, ptr: Pointer, offset: int):
        assert offset < ptr.size
        addr = self.alloc_base
        self.alloc_base += ptr.size
        logger.debug('Allocated new object for %r', ptr)
        return addr

    def copy(self, *a):
        o = super().copy(*a)
        o.alloc_base = self.alloc_base
        o.tracked    = deepcopy(self.tracked)
        return o

    def load(self, addr, size=None, condition=None, fallback=None, **kwa):
        if type(addr) is not int and not addr.concrete:
            logger.debug('Symbolic load: %r', addr)
        return super().load(addr, size=size, condition=condition, fallback=fallback, **kwa)

    def store(self, *a, **kwa):
        return super().store(*a, **kwa)

    def concretize_read_addr(self, addr: claripy.BV, strategies=None, condition=None):
        assert self.tracked is not None

        # NOTE: Careful! Comparisons and other operations on BVs have side effects!
        #       E.G. stuff like `if some_bv: ...` or `some_bv == whatever`

        solver = self.state.solver

        if addr.concrete:
            logger.error('Trying to concretize a concrete address??? %r', addr)
        else:
            logger.debug('Trying to concretize read at %r', addr)

            for ptr in self.tracked:
                off = solver.eval(addr - (ptr.bv if ptr.value is None else ptr.value))
                if 0 <= off < ptr.size:
                    break
            else:
                ptr = None
                logger.debug('No matching tracked pointers')

            if ptr is not None:
                logger.debug('Deref %r offset %r', ptr, off)

                if ptr.value is None:
                    ptr.value = self.__allocate_object(ptr, off)

                read_addr = ptr.value + off

                # We should in theory check if we can concretize to this address
                # otherwise we'll fail in stupid cases: if the library function
                # checks that the pointer we pass points to a known address,
                # this will inherently create a constraint uncompatible with the
                # concretized address we generate.
                #
                # It would be nice to check with something like
                # solver.eval(addr == read_addr), but that operation has side
                # effects and will effectively just make the solver unusable...
                # 99.9% guaranteed that we'll get an unsat later.
                #
                # For now let's just always concretize, and rely on the fact
                # that we will only use this memory model as a fallback if the
                # default one does not work.

                logger.debug('Concretized to 0x%x', read_addr)
                return [read_addr]

        return super().concretize_read_addr(addr, strategies=strategies, condition=condition)

    def eval_tracked_objects(self):
        solver = self.state.solver

        res = {}
        for ptr in self.tracked:
            if ptr.value is None:
                res[ptr] = solver.eval(self.load(ptr.bv, ptr.size), cast_to=bytes)
            else:
                res[ptr] = solver.eval(self.load(ptr.value, ptr.size), cast_to=bytes)

        return res

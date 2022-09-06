import angr
import claripy
import logging
from copy import deepcopy
from typing import Dict, Iterable, List
from angr.storage.memory_mixins import DefaultMemory

from .variables import Variable, StructPointer


logger = logging.getLogger('memory')


class CustomMemory(DefaultMemory):
    alloc_base: int
    alloc_next: int
    tracked   : List[StructPointer]

    def __init__(self, *a, **kwa):
        self.alloc_base = self.alloc_next = kwa.pop('alloc_base', 0x666abc00000)
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

    def __init_tracked(self, lst: Iterable[StructPointer]):
        assert lst is not None

        self.tracked = []
        for t in lst:
            self.tracked += t.flatten()

    def __allocate_object(self, ptr: StructPointer, offset: int):
        assert offset < ptr.size
        addr = self.alloc_next
        self.alloc_next += ptr.size

        for off, field in ptr.fields.items():
            if isinstance(field, StructPointer):
                self.store(addr + off, field.bv)

        logger.debug('Allocated new object for %r', ptr)
        return addr

    def copy(self, *a):
        o = super().copy(*a)
        o.alloc_base = self.alloc_base
        o.alloc_next = self.alloc_next
        o.tracked    = deepcopy(self.tracked)
        return o

    def load(self, addr, size=None, condition=None, fallback=None, **kwa):
        if type(addr) is not int and not addr.concrete:
            logger.debug('Symbolic load: %r', addr)
        return super().load(addr, size=size, condition=condition, fallback=fallback, **kwa)

    def store(self, addr, data, size=None, condition=None, fallback=None, **kwa):
        if type(addr) is not int and not addr.concrete:
            logger.debug('Symbolic STORE: %r', addr)
        return super().store(addr, data, size=size, condition=condition, fallback=fallback, **kwa)

    def store(self, *a, **kwa):
        return super().store(*a, **kwa)

    def concretize_read_addr(self, addr: claripy.BV, strategies=None, condition=None):
        assert self.tracked is not None

        # NOTE: Careful! Comparisons and other operations on BVs have side effects!
        #       E.G. stuff like `if some_bv: ...` or `some_bv == whatever`
        #       Maybe self.state.solver.is_true could help?

        solver = self.state.solver

        if addr.concrete:
            logger.error('Trying to concretize a concrete read address??? %r', addr)
        else:
            # logger.debug('Trying to concretize read at %r', addr)

            for ptr in self.tracked:
                off = solver.eval(addr - (ptr.bv if ptr.value is None else ptr.value))
                if 0 <= off < ptr.size:
                    break
            else:
                ptr = None
                # logger.debug('No matching tracked pointers')

            if ptr is not None:
                logger.debug('Deref read %r offset %s', ptr, hex(off) if type(off) is int else repr(off))

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

    def concretize_write_addr(self, addr: claripy.BV, strategies=None, condition=None):
        assert self.tracked is not None

        # NOTE: Careful! Comparisons and other operations on BVs have side effects!
        #       E.G. stuff like `if some_bv: ...` or `some_bv == whatever`

        solver = self.state.solver

        if addr.concrete:
            logger.error('Trying to concretize a concrete WRITE address??? %r', addr)
        else:
            # logger.debug('Trying to concretize WRITE at %r', addr)

            for ptr in self.tracked:
                off = solver.eval(addr - (ptr.bv if ptr.value is None else ptr.value))
                if 0 <= off < ptr.size:
                    break
            else:
                ptr = None
                # logger.debug('No matching tracked pointers')

            if ptr is not None:
                logger.debug('Deref WRITE %r offset %r', ptr, hex(off) if type(off) is int else repr(off))

                if ptr.value is None:
                    ptr.value = self.__allocate_object(ptr, off)

                write_addr = ptr.value + off
                logger.debug('Concretized to 0x%x', write_addr)
                return [write_addr]

        return super().concretize_write_addr(addr, strategies=strategies, condition=condition)

    def tracked_pointer_offset(self, val):
        if not isinstance(val, int):
            return None, None

        for ptr in self.tracked:
            if ptr.value is not None:
                off = val - ptr.value
                if 0 <= off < ptr.size:
                    return ptr, off

        return None, None

    def dump_tracked_memory(self):
        size = self.alloc_next - self.alloc_base
        if size > 0:
            mem = self.state.memory.load(self.alloc_base, size)
            return self.state.solver.eval(mem, cast_to=bytes)
        return None

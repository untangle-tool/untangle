#include <stddef.h>
#include "lib.h"

static unsigned flag = 0xfff;
void (*func_ptr)(void) = NULL;

static void static_func1(void) {
	if (func_ptr)
		func_ptr();
}

void exported_func1(void) {
	static_func1();
}

void exported_func2(void) {
	static_func1();
}

static void static_func2(void) {
	static_func1();
}

static void static_func3(void) {
	if (flag & 0xf000f)
		static_func1();
}

void exported_func3(void) {
	static_func3();
}

void exported_func4(void) {
	exported_func2();
}

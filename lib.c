#include <stddef.h>
#include "lib.h"

static int flag1 = 0xfff;
void (*func_ptr)(void) = NULL;

static void target_function(void){
	return;
}

static void static_func1(int a, char b) {
	if (a == 0x423452 && (flag1 | 0xff000) == 0xfffff)
		target_function();
}

void exported_func1(int a, char b) {
	static_func1(a, b);
}

void exported_func2(void) {
	static_func1(2345, 0);
}

static void static_func2(void) {
	static_func1(654, 0);
}

static void static_func3(void) {
	if (flag1 & 0xf000f)
		static_func1(2345, 0);
}

void exported_func3(void) {
	static_func3();
}

void exported_func4(void) {
	exported_func2();
}


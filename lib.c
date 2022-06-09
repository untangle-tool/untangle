#include <stddef.h>
#include "lib.h"

static unsigned flag = 0xfff;
void (*func_ptr)(void) = NULL;

static void static_func1(int a) {
	if (a == 0x423452)
		target_function();
}

void exported_func1(int a) {
	static_func1(a);
}

void exported_func2(void) {
	static_func1(2345);
}

static void static_func2(void) {
	static_func1(654);
}

static void static_func3(void) {
	if (flag & 0xf000f)
		static_func1(2345);
}

void exported_func3(void) {
	static_func3();
}

void exported_func4(void) {
	exported_func2();
}

static void target_function(void){
	return;
}
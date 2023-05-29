#ifndef _MY_DEF_H_
#define _MY_DEF_H_

#define ALWAYS_INLINE __attribute__((always_inline))

#define LOAD_CONSTANT(param, var) asm("%0 = " param " ll" : "=r"(var))

#endif
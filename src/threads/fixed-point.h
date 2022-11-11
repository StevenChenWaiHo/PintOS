#ifndef FIXEDP_H
#define FIXEDP_H

#include <stdint.h>

/*  
    Functions and macros for fixed-point calculations.
    This implementation follows the 17.14 fixed-point number representation.
    fixed_int: ----------------- --------------
                       17       ^      14
                          decimal point
*/

#define FIXED_POINT 14
#define OFFSET      (1 << FIXED_POINT)

typedef int32_t fixed_int;

static inline fixed_int convert (int num) {
    return num * OFFSET;
}

static inline int convert_int_zero (fixed_int num) {
    return num / OFFSET;
}

static inline int convert_int_nearest (fixed_int num) {
    if (num >= 0)
        return (num + OFFSET / 2) / OFFSET;
    else
        return (num - OFFSET / 2) / OFFSET;
}

static inline fixed_int add (fixed_int x, fixed_int y) {
    return x + y;
}

static inline fixed_int sub (fixed_int x, fixed_int y) {
    return x - y;
}

static inline fixed_int add_int (fixed_int x, int n) {
    return x + convert(n);
}

static inline fixed_int sub_int (fixed_int x, int n) {
    return x - convert(n);
}

static inline fixed_int mul (fixed_int x, fixed_int y) {
    return (((int64_t) x) * y) / OFFSET;
}

static inline fixed_int mul_int (fixed_int x, int n) {
    return x * n;
}

static inline fixed_int div (fixed_int x, fixed_int y) {
    return (((int64_t) x) * OFFSET) / y;
}
static inline fixed_int div_int (fixed_int x, int n) {
    return x / n;
}

#endif /* threads/fixed-point.h*/
#include <assert.h>
#include <limits.h>
#include <stdio.h>
#include "husk-tl-string-range.h"
#include "husk-tl-web-rect.h"

int main(void)
{
    assert(tl_string_range_valid(4, 4, 0));
    assert(tl_string_range_valid(4, 1, 2));
    assert(!tl_string_range_valid(4, 3, 2));
    assert(!tl_string_range_valid(4, -1, 1));
    assert(!tl_string_range_valid(4, INT_MAX, INT_MAX));
    assert(!tl_string_range_valid(INT_MAX, INT_MAX, 1));
    int b[4];
    assert(tl_web_scissor(10, 20, 30, 40, 100, 200, b));
    assert(b[0] == 10 && b[1] == 140 && b[2] == 30 && b[3] == 40);
    assert(tl_web_scissor(-10, 190, 30, 30, 100, 200, b));
    assert(b[0] == 0 && b[1] == 0 && b[2] == 20 && b[3] == 10);
    assert(!tl_web_scissor(INT_MAX, 0, INT_MAX, 1, 100, 200, b));
    assert(!tl_web_scissor(0, 0, 0, 1, 100, 200, b));
    puts("string range and WebView scissor checks passed");
}

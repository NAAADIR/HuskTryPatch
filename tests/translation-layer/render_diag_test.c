#include <assert.h>
#include "husk-tl-render-diag.h"

int main(void)
{
    int p[5][2];
    assert(!tl_diag_points(0, 20, p));
    assert(!tl_diag_points(20, -1, p));
    assert(tl_diag_points(1170, 2532, p));
    assert(p[0][0] == 585 && p[0][1] == 1266);
    for (int i = 0; i < 5; i++) {
        assert(p[i][0] >= 0 && p[i][0] < 1170);
        assert(p[i][1] >= 0 && p[i][1] < 2532);
    }
    assert(tl_diag_points(1, 1, p));
    for (int i = 0; i < 5; i++) assert(p[i][0] == 0 && p[i][1] == 0);
    assert(tl_diag_sample_frame(1) && tl_diag_sample_frame(120));
    assert(tl_diag_sample_frame(600) && tl_diag_sample_frame(1800) && tl_diag_sample_frame(3000));
    assert(!tl_diag_sample_frame(0) && !tl_diag_sample_frame(119) && !tl_diag_sample_frame(3001));
    return 0;
}

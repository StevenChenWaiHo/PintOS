# -*- perl -*-
use strict;
use warnings;
use tests::tests;
check_expected ([<<'EOF', <<'EOF']);
(exec-over-args) begin
(exec-over-args) exec() did not PANIC the kernel and returned: -1
(exec-over-args) end
exec-over-args: exit(0)
EOF
(exec-over-args) begin
(exec-over-args) exec() did not PANIC the kernel and returned: 0
(exec-over-args) end
exec-over-args: exit(0)
EOF
pass;

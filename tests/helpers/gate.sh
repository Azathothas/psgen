# The one place a shell suite decides whether an absent capability is a skip.
#
# Sourced by tests/smoke.sh, tests/workflow.sh, tests/cross.sh and
# tests/vm.sh. CI sets PSGEN_REQUIRE_ALL=1, where a missing capability is a
# failure that names it; everywhere else the check prints SKIP with the same
# reason and carries on. A suite that forked this logic could disagree with
# the others about whether a skip is allowed, and a skip that CI cannot see is
# a check that never runs. `tests/helpers/require_all_check.sh` drives both
# branches of this function so the rule cannot rot.

require_all() {
    case "${PSGEN_REQUIRE_ALL:-}" in
        "" | 0) return 1 ;;
        *) return 0 ;;
    esac
}

skip() {
    if require_all; then
        echo "FAIL: required capability missing: $*" >&2
        exit 1
    fi
    echo "SKIP: $*" >&2
}

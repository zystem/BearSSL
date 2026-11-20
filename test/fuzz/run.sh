#!/bin/sh
# Run both fuzzing targets in parallel for a given time and report.
#   sh test/fuzz/run.sh [seconds] [workers-per-target] [workdir]
# Defaults: 86400 seconds (24 hours), 12 workers per target, build-fuzz-run.
# Needs build-fuzz made by test/fuzz/build.sh (the first argument of
# build.sh can name another place: set BUILD=that). The corpus grows in
# WORKDIR/client and WORKDIR/server (seeded from test/fuzz/corpus); a crash,
# an out-of-memory or a timeout leaves a file in WORKDIR/artifacts-*.
# Exit status 0 if there is no artifact.
SECS=${1:-86400}
WORKERS=${2:-12}
WORK=${3:-build-fuzz-run}
BUILD=${BUILD:-build-fuzz}
export ASAN_OPTIONS=detect_leaks=0
for t in client server; do
	mkdir -p "$WORK/$t" "$WORK/artifacts-$t" "$WORK/log-$t"
	cp -n test/fuzz/corpus/$t/* "$WORK/$t/" 2>/dev/null
	( cd "$WORK/log-$t" && "$OLDPWD/$BUILD/fuzz_$t" "$OLDPWD/$WORK/$t" \
		-jobs=$WORKERS -workers=$WORKERS -max_total_time=$SECS \
		-timeout=10 -rss_limit_mb=2048 \
		-artifact_prefix="$OLDPWD/$WORK/artifacts-$t/" \
		> run.log 2>&1 ) &
done
wait
bad=0
for t in client server; do
	n=$(ls "$WORK/artifacts-$t" 2>/dev/null | wc -l)
	echo "$t: $n artifact(s); corpus $(ls "$WORK/$t" | wc -l) files; $(grep -h 'DONE' "$WORK/log-$t"/fuzz-*.log 2>/dev/null | tail -1 | cut -c1-100)"
	[ "$n" -gt 0 ] && bad=1
done
exit $bad

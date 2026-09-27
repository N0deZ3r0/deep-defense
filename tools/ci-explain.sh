#!/usr/bin/env bash
# Copy why a CI step failed to where anyone can read it.
#
#   bash tools/ci-explain.sh "Title" step.log
#
# GitHub shows a job's log only to someone signed in. The annotations and the
# job summary are shown to anyone who can see the run, so a red step that
# writes its reason there explains itself to whoever is looking — including a
# reviewer, or the author on a machine that cannot run the build.
title=$1
# Colour codes out first: CI asks cargo for colour, and a line that starts
# with an escape sequence does not start with "error".
log=$(mktemp)
sed -E 's/\x1b\[[0-9;]*[A-Za-z]//g' "$2" > "$log"

{
  echo "### $title"
  echo
  echo '```'
  grep -E -A6 '^(error|warning)(\[[A-Za-z0-9]+\])?: |panicked at|^failures:$' "$log" | head -150
  echo '```'
} >> "$GITHUB_STEP_SUMMARY"

# A compiler or lint error, with the place it points at.
awk '
  /^(error|warning)(\[[A-Za-z0-9]+\])?: / { message = $0; next }
  message != "" && /^ *--> / { sub(/^ *--> /, ""); print message " at " $0; message = ""; next }
' "$log" | head -10 | while IFS= read -r line; do
  echo "::error title=$title::$line"
done

# A failed test, with the lines after the panic that say what it expected.
grep -E -A3 'panicked at' "$log" | head -40 | awk '
  /panicked at/ { if (message != "") print message; message = $0; next }
  /^--$/ { next }
  { message = message "%0A" $0 }
  END { if (message != "") print message }
' | head -8 | while IFS= read -r line; do
  echo "::error title=$title::$line"
done

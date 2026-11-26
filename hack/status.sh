#!/usr/bin/env bash
# Table of work needing attention: open PRs, external items, untriaged follow-ups.
# Uses gh + jq only, two GraphQL calls. Run `hack/status.sh --help`.
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage: hack/status.sh [--help]

Prints, for the current repo (gh resolves it):
  1. Open PRs: author, head SHA, ci-ok, latest "Fable review:" verdict and the
     SHA it names (MISMATCH if not the head), unresolved threads, merge queue,
     auto-merge, mergeStateStatus.
  2. External items (author not Starefossen, not a bot): open PRs and issues,
     oldest first, days since the last maintainer reply. ! = over 1 day.
  3. Issues labelled follow-up with no p1/p2/p3 label, older than 7 days.

Needs: gh (authenticated), jq. Two API calls. Maintainer = OWNER/MEMBER/COLLABORATOR.
USAGE
}
case "${1:-}" in -h|--help) usage; exit 0;; --fixture) FIX="$2";; "") ;; *) usage >&2; exit 2;; esac

PRQ='query($o:String!,$r:String!){repository(owner:$o,name:$r){pullRequests(states:OPEN,first:50){nodes{
number title createdAt headRefOid mergeStateStatus isInMergeQueue autoMergeRequest{enabledAt}
author{login __typename} authorAssociation
commits(last:1){nodes{commit{statusCheckRollup{contexts(first:100){nodes{
 ... on CheckRun{name conclusion} ... on StatusContext{context state}}}}}}}
comments(last:50){nodes{body createdAt authorAssociation author{login __typename}}}
reviews(last:50){nodes{createdAt authorAssociation author{login __typename}}}
reviewThreads(first:100){nodes{isResolved}}}}}}'
ISQ='query($o:String!,$r:String!){repository(owner:$o,name:$r){issues(states:OPEN,first:100){nodes{
number title createdAt author{login __typename}
labels(first:30){nodes{name}}
comments(last:30){nodes{createdAt authorAssociation author{login __typename}}}}}}}'

# Shared jq helpers. shortcut: first 50 PRs / 100 issues only, paginate if the repo outgrows that.
LIB='def maint: select(.authorAssociation=="OWNER" or .authorAssociation=="MEMBER" or .authorAssociation=="COLLABORATOR")
  | select((.author.__typename // "") != "Bot");
def days: ((now - (. | fromdateiso8601)) / 86400 | floor);
def ext: (.author.__typename != "Bot") and (.author.login != "Starefossen");
def lastmaint: ([(.comments.nodes[], (.reviews.nodes[]?)) | maint | .createdAt] | max) // null;
def sinceReply: (lastmaint // .createdAt) | days;
def flag: if . > 1 then "!" else "" end;'

PRJQ="$LIB"'.data.repository.pullRequests.nodes[] | . as $p
  | ([.commits.nodes[0].commit.statusCheckRollup.contexts.nodes[]? | select(.name=="ci-ok") | .conclusion] | first // "none") as $ci
  | ([.comments.nodes[] | maint | select(.body | startswith("Fable review:"))] | last) as $f
  | (if $f == null then "" else $f.body end) as $b
  | (($b | split("\n") + [""] | .[0]) | sub("^Fable review: *";"")) as $verdict
  | (([$b | scan("Head reviewed: `?([0-9a-f]{7,40})")[0]] | first) // "") as $sha
  | [.number, .author.login, .headRefOid[0:8], $ci,
     (if $f == null then "none" else $verdict end),
     (if $f == null then "-" elif ($sha == "") then "?" else $sha[0:8] + (if ($p.headRefOid | startswith($sha)) then "" else " MISMATCH" end) end),
     ([.reviewThreads.nodes[] | select(.isResolved | not)] | length),
     (if .isInMergeQueue then "yes" else "no" end),
     (if .autoMergeRequest then "yes" else "no" end), .mergeStateStatus] | @tsv'
EXTQ="$LIB"'[($pr[0].data.repository.pullRequests.nodes[] | select(ext) | {k:"PR", n:.number, a:.author.login, t:.title, c:.createdAt, d:sinceReply}),
  ($is[0].data.repository.issues.nodes[] | select(ext) | {k:"issue", n:.number, a:.author.login, t:.title, c:.createdAt, d:sinceReply})]
  | sort_by(.c)[] | [.k, "#\(.n)", .a, "age \(.c | days)d", "reply \(.d)d \(.d | flag)", .t[0:60]] | @tsv'
FUQ="$LIB"'.data.repository.issues.nodes[] | select([.labels.nodes[].name] as $l | ($l | index("follow-up")) and ([$l[] | select(test("^p[123]$"))] | length == 0))
  | select((.createdAt | days) > 7) | ["#\(.number)", "\(.createdAt | days)d", .title[0:70]] | @tsv'

if [ -n "${FIX:-}" ]; then PR=$(cat "$FIX/prs.json"); IS=$(cat "$FIX/issues.json")
else
  NWO=$(gh repo view --json owner,name -q '.owner.login+" "+.name'); set -- $NWO
  PR=$(gh api graphql -f query="$PRQ" -f o="$1" -f r="$2")
  IS=$(gh api graphql -f query="$ISQ" -f o="$1" -f r="$2")
fi

T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
printf %s "$PR" > "$T/pr"; printf %s "$IS" > "$T/is"
echo "== Open PRs"
{ printf 'PR\tauthor\thead\tci-ok\tfable\tfable-sha\tthreads\tqueue\tauto\tmerge-state\n'
  jq -r "$PRJQ" <<<"$PR"; } | column -t -s $'\t'
echo; echo "== External items (oldest first)"
jq -nr --slurpfile pr "$T/pr" --slurpfile is "$T/is" "$EXTQ" | column -t -s $'\t'
echo; echo "== follow-up without p1/p2/p3, older than 7 days"
jq -r "$FUQ" <<<"$IS" | column -t -s $'\t'

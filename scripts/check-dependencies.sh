#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

CONFIGURATION="runtimeClasspath"

usage() {
    cat <<EOF
Usage: $(basename "$0") [--test] <command> [options]

Options:
  --test                     Use testRuntimeClasspath instead of runtimeClasspath

Commands:
  tree [subproject]          Show full dependency tree (default: all subprojects)
  search <artifact>          Search for a specific dependency across all subprojects
  insight [subproject] <artifact>  Show why a dependency is included (transitive path)
  outdated                   List outdated dependencies
  duplicates                 Find duplicate/conflicting dependency versions
  checkvuln <group:artifact:version>  Check a specific component version for known vulnerabilities
  audit                      List all dependencies with their parent subproject and vulnerability status (CSV)

Examples:
  $(basename "$0") tree oidc-api
  $(basename "$0") --test tree oidc-api
  $(basename "$0") search nimbusds
  $(basename "$0") insight oidc-api com.nimbusds:nimbus-jose-jwt
  $(basename "$0") outdated
  $(basename "$0") duplicates
  $(basename "$0") checkvuln com.nimbusds:nimbus-jose-jwt:9.31
  $(basename "$0") audit
EOF
}

run_gradle() {
    "$PROJECT_DIR/gradlew" -p "$PROJECT_DIR" --no-configuration-cache "$@"
}

cmd_tree() {
    local subproject="${1:-}"
    if [[ -n "$subproject" ]]; then
        run_gradle ":${subproject}:dependencies" --configuration "$CONFIGURATION"
    else
        run_gradle allDeps --configuration "$CONFIGURATION"
    fi
}

cmd_search() {
    local artifact="${1:?Error: provide an artifact name to search for}"
    echo "Searching for '$artifact' in $CONFIGURATION across all subprojects..."
    run_gradle allDeps --configuration "$CONFIGURATION" | grep -i "$artifact" || echo "No matches found."
}

cmd_insight() {
    if [[ -n "${2:-}" ]]; then
        local subproject="$1"
        local artifact="$2"
        run_gradle ":${subproject}:dependencyInsight" --configuration "$CONFIGURATION" --dependency "$artifact"
    else
        local artifact="${1:?Error: provide an artifact (e.g. com.nimbusds:nimbus-jose-jwt)}"
        grep "^include " "$PROJECT_DIR/settings.gradle" | sed "s/include '//;s/'//" | while read -r sub; do
            echo "=== :${sub} ==="
            run_gradle ":${sub}:dependencyInsight" --configuration "$CONFIGURATION" --dependency "$artifact" 2>/dev/null | grep -v "^$" || true
        done
    fi
}

cmd_outdated() {
    run_gradle dependencyUpdates -Drevision=release 2>/dev/null || \
        echo "Note: requires the 'com.github.ben-manes.versions' plugin. Run 'tree' instead."
}

cmd_duplicates() {
    echo "Checking for version conflicts in $CONFIGURATION across subprojects..."
    run_gradle allDeps --configuration "$CONFIGURATION" | \
        grep -E '^\+---|\\---' | \
        sed 's/.*--- //' | \
        sort | uniq -c | sort -rn | \
        awk '$1 > 1 {print}' | head -40
}

cmd_checkvuln() {
    local coordinate="${1:?Error: provide group:artifact:version (e.g. com.nimbusds:nimbus-jose-jwt:9.31)}"
    local group name version
    IFS=':' read -r group name version <<< "$coordinate"
    [[ -z "$version" ]] && echo "Error: version required (format: group:artifact:version)" && exit 1
    local purl="pkg:maven/${group}/${name}@${version}"
    echo "Checking vulnerabilities for ${purl}..."
    local response
    response=$(curl -s -X POST "https://api.osv.dev/v1/query" \
        -H "Content-Type: application/json" \
        -d "{\"package\":{\"purl\":\"$purl\"}}")
    echo "$response" | python3 -c "
import sys,json
data=json.load(sys.stdin)
vulns=data.get('vulns',[])
if not vulns:
    print('No known vulnerabilities found.')
else:
    print(f'Found {len(vulns)} vulnerability(ies):')
    for v in vulns:
        severity=next((s['score'] for s in v.get('severity',[])),'-')
        cves=', '.join(a for a in v.get('aliases',[]) if a.startswith('CVE-')) or 'No CVE'
        print(f\"  - {v['id']} [{cves}] [CVSS {severity}] {v.get('summary','No summary')}\")
"
}

cmd_audit() {
    echo "subproject,group,artifact,version,has_vulnerabilities,cves"
    run_gradle allDeps --configuration "$CONFIGURATION" 2>/dev/null | \
    python3 -c "
import sys,json,re,urllib.request

deps = {}
current_project = ''
for line in sys.stdin:
    line = line.rstrip()
    m = re.match(r\"^Project ':(.+)'\", line)
    if m:
        current_project = m.group(1)
        continue
    # Match dependency lines, handling -> version upgrades and (c)/(*)
    dm = re.search(r'--- (\S+):(\S+):(\S+)', line)
    if dm and current_project:
        if '(c)' in line:
            continue
        g, a, v = dm.group(1), dm.group(2), dm.group(3)
        # Handle version range or upgrade: e.g. '2.25.3 -> 2.25.4' or '[1.3,2.4] -> 2.4.10'
        arrow = re.search(r'-> (\S+)', line)
        if arrow:
            v = arrow.group(1)
        # Strip trailing markers
        v = re.sub(r' \(\*\)$', '', v).strip()
        key = (g, a, v)
        if key not in deps:
            deps[key] = current_project

purls = [f'pkg:maven/{g}/{a}@{v}' for g, a, v in deps]
# Query OSV in batches of 1000
vuln_map = {}
for i in range(0, len(purls), 1000):
    batch = purls[i:i+1000]
    queries = [{'package':{'purl':p}} for p in batch]
    req = urllib.request.Request('https://api.osv.dev/v1/querybatch',
        data=json.dumps({'queries':queries}).encode(),
        headers={'Content-Type':'application/json'})
    resp = json.loads(urllib.request.urlopen(req).read())
    for j, r in enumerate(resp.get('results',[])):
        if r.get('vulns'):
            cves = set()
            for vuln in r['vulns']:
                vid = vuln.get('id','')
                if vid.startswith('CVE-'):
                    cves.add(vid)
                # Fetch full details to get aliases
                try:
                    detail_req = urllib.request.Request(f'https://api.osv.dev/v1/vulns/{vid}')
                    detail = json.loads(urllib.request.urlopen(detail_req).read())
                    for alias in detail.get('aliases',[]):
                        if alias.startswith('CVE-'):
                            cves.add(alias)
                except Exception:
                    pass
            if cves:
                vuln_map[batch[j]] = sorted(cves)

for (g, a, v), subproject in sorted(deps.items()):
    purl = f'pkg:maven/{g}/{a}@{v}'
    cves = vuln_map.get(purl, [])
    has_vuln = 'true' if cves else 'false'
    cves_str = ';'.join(cves) if cves else ''
    print(f'{subproject},{g},{a},{v},{has_vuln},{cves_str}')
"
}

if [[ "${1:-}" == "--test" ]]; then
    CONFIGURATION="testRuntimeClasspath"
    shift
fi

case "${1:-}" in
    tree)       cmd_tree "${2:-}" ;;
    search)     cmd_search "${2:-}" ;;
    insight)    cmd_insight "${2:-}" "${3:-}" ;;
    outdated)   cmd_outdated ;;
    duplicates) cmd_duplicates ;;
    checkvuln)  cmd_checkvuln "${2:-}" ;;
    audit)      cmd_audit ;;
    -h|--help|help) usage ;;
    *)          usage; exit 1 ;;
esac

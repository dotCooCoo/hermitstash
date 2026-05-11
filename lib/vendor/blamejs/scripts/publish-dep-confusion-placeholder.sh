#!/usr/bin/env bash
#
# Publish placeholder packages for the unscoped names attackers would
# typosquat against the framework. Run ONCE per maintainer rotation
# to take + hold the namespaces. The placeholder packages do nothing
# (just `console.error` + exit 1 + a README pointing operators at
# the canonical `@blamejs/core`); their value is denying attackers
# the names.
#
# Names to hold:
#   - blamejs                    (unscoped main)
#   - blame-js                   (kebab-case typo)
#   - blamejs-core               (operators who type the scope flat)
#
# Why this matters:
#
#   v0.8.61 dependency-confusion attack pattern: an attacker publishes
#   `blamejs@99.0.0` to the public npm registry. An operator with a
#   private registry that has `@blamejs/core` AND a fallback to public
#   npm types `npm install blamejs` (forgetting the scope), the
#   private registry lookup misses (no unscoped package), npm falls
#   through to public, the attacker's tarball runs lifecycle scripts
#   on the operator's CI machine. Holding the unscoped name with a
#   placeholder denies the squat path.
#
# Run flow (manual — npm doesn't have a workflow-driven equivalent):
#
#   bash scripts/publish-dep-confusion-placeholder.sh
#
# Reads NPM_TOKEN from env. Refuses if the placeholder is already
# published by a different owner (signal that the squat already
# happened — file a takedown ticket, don't try to overwrite).

set -euo pipefail

if [ -z "${NPM_TOKEN:-}" ]; then
  echo "::error::NPM_TOKEN env var required"
  exit 1
fi

PLACEHOLDER_VERSION="0.0.1-placeholder"
WORKDIR="$(mktemp -d)"

PLACEHOLDER_NAMES=(
  "blamejs"
  "blame-js"
  "blamejs-core"
)

for NAME in "${PLACEHOLDER_NAMES[@]}"; do
  echo "::group::Checking $NAME"
  EXISTING_OWNER=$(npm owner ls "$NAME" 2>/dev/null | head -1 | awk '{print $1}' || echo "")
  if [ -n "$EXISTING_OWNER" ] && [ "$EXISTING_OWNER" != "blamejs" ] && [ "$EXISTING_OWNER" != "<your-npm-org>" ]; then
    echo "::warning::$NAME is owned by '$EXISTING_OWNER' (not the framework org). File an npm Trust & Safety report at https://www.npmjs.com/support if this is squatting."
    echo "::endgroup::"
    continue
  fi

  PKG_DIR="$WORKDIR/$NAME"
  mkdir -p "$PKG_DIR"
  cat > "$PKG_DIR/package.json" <<EOF
{
  "name": "$NAME",
  "version": "$PLACEHOLDER_VERSION",
  "description": "Placeholder — the canonical package is @blamejs/core. This unscoped name is held by the framework maintainers to defend against dependency-confusion typosquats.",
  "main": "index.js",
  "license": "Apache-2.0",
  "homepage": "https://blamejs.com",
  "repository": { "type": "git", "url": "git+https://github.com/blamejs/blamejs.git" },
  "keywords": ["placeholder", "blamejs", "use @blamejs/core"]
}
EOF
  cat > "$PKG_DIR/index.js" <<'EOF'
"use strict";
console.error(
  "[" + require("./package.json").name + "] You depended on the unscoped " +
  "placeholder package. The canonical blamejs framework is published as " +
  "@blamejs/core. Update your import:\n\n" +
  "  npm install @blamejs/core\n\n" +
  "  var b = require(\"@blamejs/core\");\n"
);
process.exit(1);
EOF
  cat > "$PKG_DIR/README.md" <<EOF
# $NAME — placeholder

This is a placeholder package held by the blamejs framework maintainers
to defend against dependency-confusion typosquats. The canonical
package is **[\`@blamejs/core\`](https://www.npmjs.com/package/@blamejs/core)**.

\`\`\`
npm install @blamejs/core
\`\`\`
EOF

  echo "Publishing $NAME@$PLACEHOLDER_VERSION..."
  (cd "$PKG_DIR" && npm publish --access public)
  echo "::endgroup::"
done

echo "[dep-confusion-placeholder] done"

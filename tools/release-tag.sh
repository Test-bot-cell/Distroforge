#!/bin/sh
set -eu

# Cut the signed Git tag that anchors a changelog version to a commit.
#
# debian/changelog carried 46 versions while this repository carried no tags at all, so
# nothing recorded which commit any of those versions was. This is the missing half of
# that: one signed tag per packaging version, named the way debian/gbp.conf pins it.
#
# It creates the tag and stops. Publishing is a separate command on purpose -- a tag that
# has been pushed must not be moved afterwards, so the push is typed knowingly instead of
# happening as a side effect of asking for a tag.

die() {
    echo "release-tag: $*" >&2
    exit 1
}

command -v gbp >/dev/null 2>&1 || die "git-buildpackage is not installed"
command -v dpkg-parsechangelog >/dev/null 2>&1 || die "dpkg-dev is not installed"
git rev-parse --show-toplevel >/dev/null 2>&1 || die "not inside a Git repository"

cd "$(git rev-parse --show-toplevel)"
test -f debian/changelog || die "debian/changelog is not at the repository root"

version=$(dpkg-parsechangelog -l debian/changelog -S Version)
distribution=$(dpkg-parsechangelog -l debian/changelog -S Distribution)
branch=$(gbp config tag.debian-branch)
format=$(gbp config tag.debian-tag)
sign=$(gbp config tag.sign-tags)
signing_key=$(git config user.signingkey || true)

# What the tag is called is gbp's to compute and not ours. DEP-14 mangling turns ':' into
# '%', '~' into '_' and '..' into '.#.', and a second implementation of those rules in sed
# would drift from the one that actually creates the tag. /usr/bin/python3 rather than
# python3: the project's .venv is built without system site packages, so the python on
# PATH may be one that cannot import gbp.
tag=$(/usr/bin/python3 -c 'import sys
from gbp.deb.git import DebianGitRepository
print(DebianGitRepository.version_to_tag(sys.argv[1], sys.argv[2]))' "$format" "$version") ||
    die "could not ask gbp what it would name the tag for $version"

test "$sign" = "True" ||
    die "debian/gbp.conf no longer sets sign-tags = True, and an unsigned release tag is not one"
test "$distribution" != "UNRELEASED" ||
    die "the newest changelog entry is UNRELEASED, so a tag would name a version nothing released"
test -n "$signing_key" ||
    die "git config user.signingkey is unset, so this cannot report which key signed the tag"
test -z "$(git status --porcelain)" ||
    die "the working tree is not clean, and a tag must name a committed state"

on_branch=$(git rev-parse --abbrev-ref HEAD)
test "$on_branch" = "$branch" ||
    die "on '$on_branch', but debian/gbp.conf makes '$branch' the release branch"

git verify-commit HEAD >/dev/null 2>&1 ||
    die "HEAD carries no good signature, and a signed tag over an unverifiable commit proves nothing"

if git rev-parse -q --verify "refs/tags/$tag" >/dev/null 2>&1; then
    die "$tag already exists here; a version is tagged once, so bump the changelog instead"
fi

# A tag naming a commit nobody else can resolve means nothing to anyone, so these consult
# the remote and there is deliberately no offline path around them. Captured without a
# pipe: through one, the exit status read would be cut's and a failed ls-remote would look
# like a success that found nothing.
remote_branch=$(git ls-remote origin "refs/heads/$branch") || die "cannot reach origin"
remote_head=$(printf '%s\n' "$remote_branch" | cut -f1)
test -n "$remote_head" || die "origin has no $branch"
test "$remote_head" = "$(git rev-parse HEAD)" ||
    die "HEAD is not what origin/$branch points at, so push the branch before tagging it"
remote_tag=$(git ls-remote --tags origin "refs/tags/$tag") || die "cannot reach origin"
test -z "$remote_tag" || die "$tag already exists on origin"

echo "release-tag: $tag at $(git rev-parse --short HEAD) on $branch, signed with $signing_key"
gbp tag

# Predicted above, verified here. If gbp's naming or its signing ever stops matching what
# this script announced, that has to fail loudly rather than pass quietly.
test "$(git cat-file -t "$tag")" = "tag" || die "$tag is not an annotated tag"
git tag --points-at HEAD | grep -Fqx "$tag" || die "gbp created no $tag at HEAD"
git verify-tag "$tag" >/dev/null 2>&1 || die "$tag carries no good signature"

echo "release-tag: created and verified. Publish it with:"
echo "    git push origin refs/tags/$tag"

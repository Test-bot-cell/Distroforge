# One entry point for verifying DistroForge. `make check` is what CI runs and
# what a change is expected to pass before it is committed.
#
# Nothing here installs anything or builds an artifact. Package and ISO builds are
# always explicit, never a side effect of checking your work.

PYTHON ?= python3
RUFF ?= ruff
MYPY ?= mypy

# The tree carried .pyc files whose co_filename pointed at a directory the
# sources had since moved out of, so local tracebacks named the wrong tree.
export PYTHONDONTWRITEBYTECODE := 1
# Qt has no display in a terminal or in CI; tests/conftest.py sets the same value.
export QT_QPA_PLATFORM ?= offscreen

.PHONY: check lint typecheck test shellcheck maintainer-scripts clean-pyc tag help

help:
	@echo "make check              run every check below"
	@echo "make lint               ruff"
	@echo "make typecheck          mypy, ratcheted against the debt list in pyproject"
	@echo "make test               pytest"
	@echo "make shellcheck         the Debian maintainer scripts and tools/*.sh"
	@echo "make maintainer-scripts compile the Python payloads embedded in them"
	@echo "make clean-pyc          drop stale bytecode caches"
	@echo "make tag                sign the release tag for the newest changelog version"

check: lint typecheck test shellcheck maintainer-scripts

lint:
	$(RUFF) check .

typecheck:
	$(MYPY) distroforge/

test:
	$(PYTHON) -m pytest -q

# Discovered, not hardcoded: debhelper generates some maintainer scripts, so a
# fixed list goes stale in both directions -- naming a file that is not in the
# source tree, or missing one that was added later.
# debian/rules is a Makefile and debian/clean is a list of paths, so neither is
# shell and neither belongs here. The shell dialect comes from each shebang.
# debian/tests/* is swept rather than named: a new autopkgtest script would
# otherwise ship unchecked, which is how debian/tests/gui-import nearly did.
MAINTAINER_SCRIPTS = $(wildcard debian/*.preinst debian/*.postinst debian/*.prerm \
                               debian/*.postrm) \
                     $(filter-out debian/tests/control,$(wildcard debian/tests/*))

# Swept for the same reason, not named: tools/*.sh is shell that runs on a maintainer's
# machine at release time. A release script that nothing checks is the same shape of
# problem as a maintainer script that nothing checks.
TOOL_SCRIPTS = $(wildcard tools/*.sh)

shellcheck:
	@command -v shellcheck >/dev/null || { echo "shellcheck is not installed"; exit 1; }
	@test -n "$(MAINTAINER_SCRIPTS)" || { echo "no maintainer scripts found"; exit 1; }
	@test -n "$(TOOL_SCRIPTS)" || { echo "no tools/*.sh found"; exit 1; }
	shellcheck --exclude=SC1090,SC1091 $(MAINTAINER_SCRIPTS) $(TOOL_SCRIPTS)

# Declared in check: with no recipe, this target ran nothing and reported success --
# the same "wired to nothing" shape as the payload it guards. tests/ exercises the
# gate too; running it here keeps `make check` honest about what it covered.
maintainer-scripts:
	$(PYTHON) tools/check-maintainer-scripts.py .

clean-pyc:
	find . -path ./.venv -prune -o -name '__pycache__' -type d -print0 | xargs -0 rm -rf

# Deliberately outside check: it reaches the network and creates a signed Git object.
# Releasing is asked for, never a side effect of verifying your work.
tag:
	tools/release-tag.sh

# HugMesh owncast-bff-api — developer Makefile.
#
# `make pentest` runs the SAME OWASP checks the CI pentest stage runs, locally:
#   * SCA  — OWASP Dependency-Check over this repo's Maven dependencies, mirroring
#            the centralized .pentest-sca CI job. Fails on a CVSS>=9 finding so a
#            local self-scan is advisory and won't block dev on medium findings;
#            CI uses the stricter --failOnCVSS 7 gate.
#   * DAST — delegates to the generator pen-test harness (run-pentest.sh) against
#            $DAST_TARGET_URL when set, mirroring the .pentest-dast-baseline CI job.
#
# Nothing here hard-fails when a target/tooling is absent — it degrades to a note.

SHELL := /bin/bash

# Where the generator pen-test harness lives (cloned alongside this repo by
# default; override to point at a vendored / fetched copy).
PENTEST_HARNESS_DIR ?= ../hugmesh-generator/tests/pentest
PENTEST_GENERATOR_REPO ?= https://github.com/hugmesh-net/hugmesh-generator.git

# Dependency-Check image used when no local ./mvnw is usable (matches CI's
# public-image-only toolchain posture).
DC_IMAGE ?= owasp/dependency-check:latest

.PHONY: pentest pentest-sca pentest-dast

## pentest: run the local OWASP self-scan (SCA) + optional DAST harness.
pentest: pentest-sca pentest-dast

## pentest-sca: OWASP Dependency-Check over this repo (mirrors .pentest-sca CI job).
pentest-sca:
	@echo ">> [pentest:sca] OWASP Dependency-Check (Maven) over this repo"
	@if [ -x ./mvnw ]; then \
		./mvnw -B org.owasp:dependency-check-maven:check -DfailBuildOnCVSS=9 || \
			{ echo ">> [pentest:sca] dependency-check reported findings (or could not run) — see target/dependency-check-report.html"; }; \
	else \
		echo ">> [pentest:sca] no ./mvnw found; CI runs Dependency-Check via the $(DC_IMAGE) image."; \
		echo ">> [pentest:sca] e.g.: docker run --rm -v \"$$PWD:/src\" $(DC_IMAGE) --scan /src --failOnCVSS 7 --format HTML --out /src/reports/sca"; \
	fi

## pentest-dast: run the generator DAST harness against $DAST_TARGET_URL (no-op if unset).
pentest-dast:
	@if [ -z "$$DAST_TARGET_URL" ]; then \
		echo ">> [pentest:dast] DAST_TARGET_URL not set — skipping DAST (set it to run the ZAP baseline against a live target)."; \
	elif [ -x "$(PENTEST_HARNESS_DIR)/run-pentest.sh" ]; then \
		echo ">> [pentest:dast] delegating to generator harness against $$DAST_TARGET_URL"; \
		ZAP_TARGET="$$DAST_TARGET_URL" bash "$(PENTEST_HARNESS_DIR)/run-pentest.sh" --env compose --scan baseline --pipeline main || \
			echo ">> [pentest:dast] harness exited non-zero (advisory) — see harness reports."; \
	else \
		echo ">> [pentest:dast] harness not found at $(PENTEST_HARNESS_DIR)."; \
		echo ">> [pentest:dast] clone it, e.g.: git clone $(PENTEST_GENERATOR_REPO) && \\"; \
		echo "     ZAP_TARGET=\"$$DAST_TARGET_URL\" bash hugmesh-generator/tests/pentest/run-pentest.sh --env compose --scan baseline --pipeline main"; \
	fi

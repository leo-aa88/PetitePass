.PHONY: setup install-requirements install-dev test lint typecheck build install uninstall clean

setup:
	python3 -m venv .venv

install-requirements:
	pip3 install -r requirements.txt

install-dev:
	pip3 install -r requirements-dev.txt

# Install the application (and the `petitepass` console script) via pip.
install:
	pip3 install .

uninstall:
	pip3 uninstall -y petitepass

test:
	python3 -m pytest tests -q

lint:
	ruff check src tests

typecheck:
	mypy

# Standalone single-file binary (no Python required at runtime). Requires the
# dev dependencies (PyInstaller); run `make install-dev` first. --windowed so a
# GUI app does not spawn a console window.
build:
	pyinstaller --onefile --windowed --name petitepass \
		--add-data "src/petitepass/core/data/10k-most-common.txt:petitepass/core/data" \
		src/petitepass/app.py

clean:
	rm -rf build dist *.spec __pycache__

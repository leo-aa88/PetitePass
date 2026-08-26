.PHONY: setup install-requirements install-dev test lint build install uninstall clean

setup:
	python3 -m venv .venv

install-requirements:
	pip3 install -r requirements.txt

install-dev:
	pip3 install -r requirements-dev.txt

test:
	python3 -m pytest tests -q

lint:
	ruff check src tests

build:
	pyinstaller --onefile --name petitepass src/main.py

install: build
	install -Dm755 dist/petitepass /usr/bin/petitepass

uninstall:
	rm -f /usr/bin/petitepass

clean:
	rm -rf build dist *.spec __pycache__

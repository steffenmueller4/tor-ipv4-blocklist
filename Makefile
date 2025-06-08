init:
	pip install -r requirements.txt

flake8:
	flake8 ./main.py

.PHONY: init test
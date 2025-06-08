init:
	pip install -r requirements.txt

pylint:
	pylint ./main.py

.PHONY: init test
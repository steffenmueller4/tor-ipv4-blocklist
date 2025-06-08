init:
	pip install -r requirements.txt && python -m venv ./venv

pylint:
	pylint ./main.py

run:
	python ./main.py

.PHONY: init test
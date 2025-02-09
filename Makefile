run:
	@python merkle.py

test:
	@python -m unittest discover -v

clean:
	@rm -rf __pycache__

.PHONY: run test clean

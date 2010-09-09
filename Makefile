VIRTUALENV = virtualenv
BIN = bin

.PHONY: all build check coverage test mysqltest doc alltest

all:	build test

build:
	$(VIRTUALENV) --no-site-packages .
	$(BIN)/easy_install nose
	$(BIN)/easy_install coverage
	$(BIN)/easy_install flake8
	$(BIN)/python setup.py develop

check:
	rm -rf synccore/templates/*.py
	$(BIN)/flake8 synccore

coverage:
	$(BIN)/nosetests -s --cover-html --cover-html-dir=html --with-coverage --cover-package=synccore synccore
	WEAVE_TESTFILE=mysql $(BIN)/nosetests -s --cover-html --cover-html-dir=html --with-coverage --cover-package=synccore synccore 

test:
	$(BIN)/nosetests -s synccore

mysqltest:
	WEAVE_TESTFILE=mysql $(BIN)/nosetests -s synccore

ldaptest:
	WEAVE_TESTFILE=ldap $(BIN)/nosetests -s synccore


alltest: test mysqltest ldaptest

doc:
	$(BIN)/sphinx-build doc/source/ doc/build/


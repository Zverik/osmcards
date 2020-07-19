run: venv
	FLASK_APP=www FLASK_ENV=development venv/bin/flask run

venv:
	python3 -m venv $@
	venv/bin/pip install -r requirements.txt

tr-extract: venv
	venv/bin/pybabel extract -F babel.cfg -k _l -k _p:1c,2 -o messages.pot .
	tx push -s

tr-update: venv
	tx pull -a
	for lang in www/translations/*; do sed -i '/^#.*fuzzy/d' $$lang/LC_MESSAGES/messages.po; done
	venv/bin/pybabel compile -d www/translations

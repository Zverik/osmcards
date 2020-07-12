.PHONY: run

run:
	FLASK_APP=www FLASK_ENV=development pipenv run flask run

tr-extract:
	pipenv run pybabel extract -F babel.cfg -k _l -o messages.pot .
	tx push -s

tr-update:
	tx pull -a
	for lang in www/translations/*; do sed -i '/^#.*fuzzy/d' $$lang/LC_MESSAGES/messages.po; done
	pipenv run pybabel compile -d www/translations

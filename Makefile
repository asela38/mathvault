.PHONY: setup demo-bloom migrate seed run test check

setup:            ## install deps (uv), migrate, build demo Bloom filter, seed data
	uv sync
	$(MAKE) migrate demo-bloom seed

migrate:
	uv run python manage.py migrate

demo-bloom:       ## small Bloom filter from Django's bundled 20k list + extras (dev/test only)
	uv run python scripts/make_demo_list.py data/pwned/demo-passwords.txt
	uv run python manage.py build_pwned_bloom --passwords data/pwned/demo-passwords.txt --out data/pwned/current.bloom --fp-rate 0.0001

seed:
	uv run python manage.py seed_demo

run:
	uv run python manage.py runserver

test:
	uv run pytest

check:
	uv run python manage.py check
	uv run python manage.py check_pwned_bloom --probe password --probe 'P@ssw0rd' --probe 'correct-horse-ellipse-perimeter-9'

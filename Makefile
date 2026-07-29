.PHONY: test fuzz prop bench perf profile lint type build docs all
test:    ; python -m unittest discover -s tests -q
fuzz:    ; python -m unittest tests.test_fuzz -q
prop:    ; python -m unittest tests.test_property -q
bench:   ; python cli.py --benchmark benchmark/corpus.json --out /tmp/bench
perf:    ; python tools/benchmark_perf.py
profile: ; python tools/profile_run.py
lint:    ; ruff check glasscage cli.py
type:    ; mypy glasscage
build:   ; python -m build
docs:    ; python tools/gen_api_docs.py
all: test fuzz prop bench

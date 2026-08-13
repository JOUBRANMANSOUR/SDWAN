# Agent accuracy evaluation

`tests/golden/agent_accuracy_cases.yaml` contains positive, unavailable, invalid,
conceptual, and mixed cases for `gpt-oss:20b-cloud`. Run
`PYTHONPATH=$PWD /home/joubran/ryu-venv38/bin/python sdwan/scripts/run_agent_accuracy_eval.py`
after sourcing `sdwan/.env` and ensuring the live lab is available.

The included runner validates the golden-contract fixtures and validator failure
paths. A real model measurement remains an explicit live-lab procedure because it
starts Ollama and Claude Code; it is not claimed by the fixture-only run. Test-only
unsupported-claim examples are never used as a production word blacklist.

# Management testing

Run: `source ~/ryu-venv38/bin/activate && PYTHONPATH=$PWD python -m unittest discover -s sdwan_v5/tests -p 'test_*.py' -v`.

The suite is unprivileged. Live runtime endpoints require a running Docker/Containernet topology and report `UNAVAILABLE` if it is absent; unit tests do not prove live routing or failover.

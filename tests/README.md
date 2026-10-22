# Tests

These are [btest](https://github.com/zeek/btest) tests, run via:

```sh
cd tests && btest -c btest.cfg
```

## Generating baselines

The first time (or whenever expected output changes), record the baseline:

```sh
cd tests && btest -c btest.cfg -U     # update/record baselines
```

This creates `Baseline/<test-name>/output`. Commit the `Baseline/` directory.

Install btest if needed:

```sh
pip install btest
```

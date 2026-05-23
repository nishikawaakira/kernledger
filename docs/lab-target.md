# Lab target fixture

`ir-lab-target` is a small helper for self-testing `kernledger
collect` against something intentionally noisy:

- one long-lived parent process
- optional child processes (visible in `pstree` / `ps`)
- one TCP listener
- one UDP listener
- heartbeat logs and status files under `/tmp`

It is for sandbox validation only.

## Build

On your development machine:

```sh
make build-fixture
# -> dist/ir-lab-target-linux-amd64
```

Or build natively on the current machine:

```sh
make build-fixture-host
```

## Run

Example on a Linux host:

```sh
export IR_LAB_TAG=CASE-VERIFY-1

./dist/ir-lab-target-linux-amd64 \
  --state-dir /tmp/ir-lab-target \
  --tcp 0.0.0.0:18080 \
  --udp 0.0.0.0:18081 \
  --children 2
```

This creates:

- `/tmp/ir-lab-target/parent-status.json`
- `/tmp/ir-lab-target/child-0-status.json`
- `/tmp/ir-lab-target/child-1-status.json`
- `/tmp/ir-lab-target/*heartbeat.log`

## Touch the sockets

Create a little network activity so `ss` output is less empty:

```sh
curl http://127.0.0.1:18080 || true
printf 'ping\n' | nc -u -w1 127.0.0.1 18081
```

The TCP listener returns one JSON object and closes. The UDP listener
replies with a short text line.

## What `collect` should see

After the fixture is running, these commands should become more useful:

- `ps auxwwf`
- `pstree -alp`
- `ss -antp`
- `ss -uanp`
- `env` when `--include-env` is used and `IR_LAB_TAG` is set

The heartbeat/status files are not collected automatically unless you
copy them into a path that your active distro adapter already includes,
or extend the adapter for a local experiment.

## Stop

Send `Ctrl+C` in the foreground terminal, or:

```sh
pkill -f ir-lab-target
```

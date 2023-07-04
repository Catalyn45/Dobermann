# Dobermann

Doberman is an Intrusion Detection System (IDS) which uses a series of rules that
help define malicious network activity and uses those rules to find packets that match
against them, generating alerts for users.

## Dependencies

- libevent
- libpcap
- libcurl

## Building

To build the project use `make`.

## Running

You need to have `admin` privileges to run the project because `raw sockets` can't be bound
as a normal user.

You need to have a config file named `config.json`. You can check or directly use by copying `config.json.example` for
an example.

You need to have `http_scripts.json`. You can check or directly use by copying `http_scripts.json.example` for
an example.

You need to have `profiling_patterns.json`. You can check or directly use by copying `profiling_patterns.json.example` for
an example.


# ip2drop

Find malicious IP addresses through executed command and send it's to firewalld `drop` zone for relaxing)

It is a interval-based solution, you can setup execute commands, threshold and running intervals.

## Arguments

* `-c` - command execution. Bash or another command which `ip2drop` will run
* `-l` - log file name. `ip2drop` will export IP addresses from this log file and this IP on threshold exceeding
* `-t` - threshold. Threshold exceeding value. Example: failure root login attempts through ssh max threshold - `1`
* `-o` - drop timeout period
* `-g` - group name - this name will be defined in DB as determinate rule
* `-d` - delete IP from DB and Drop
* `-e` - excludes ip list, separated with space (example: `127.0.0.1 1.1.1.1`)
* `-r` - rebind - reset ipset and DB (with DB backup)
* `-s` - get statistics without IP droping. This argument can be used for command execution testing
* `-p` - print database statistics
* `-pr` - print last scan time/count from DB
* `-pc` - prpint current configuration / script environments

Works with multiple conditions:

```
./ip2drop.py -l ssh-ctl.log -t 1 -c "journalctl -u ssh -S today --no-tail | grep 'Connection closed by authenticating user root'"
```

If threshold value (`-t 1`) will exceed, founded IP from log (`-l ssh-ctl.log`) will send to firewalld `drop` zone.
If you want to review statistics for, jus add `-s` argument to command.

Result:

```
Checking db.sql schema...
Checking db.sql schema: Done.
Log file: /User/ip2drop/log/ssh-ctl.log created. Done.
Log catalog: /User/ip2drop/log created. Done.
Checking threshold: 1
xxx.xxx.xx.x -> 2
success
```

This is real-time firewalld action (not `--permanent`) for reset blocking IPs you can reload firewalld.

## Config Options

* `IP_TIMEOUT` - drop time in seconds
* `IP_THRESHOLD` - number of repetitions of the address in the log
* `EXPORT_COMMAND` - log exporter
* `GROUP_NAME` - log file name, stored in `logs` catalog
* `EXPORT_TO_UPLOAD` - collect founded logs to export list for upload on remote server
* `DROP_DIRECTLY` - drop immediately, without DB storing
* `SKIP_DEFAULT_RULE` - Skip `[DEFAULT]` rule from `config.ini`

## Main Config

* `IP_EXCLUDES` - Exlude IP list from `drop` actions (only logging)
* `SKIP_DEFAULT_RULE` - Skip `[DEFAULT]` rule from `config.yml`
* `UPLOAD` - Generate upload file with dropped IP list, with name <Server_Name>_upload.txt
* `UPLOAD_TO_SERVER` - Upload generated file to remote web server (like [cactusd](https://github.com/m0zgen/cactusd))
* `UPLOAD_SERVERS` - Remote servers address list

## Command Examples

Set custom threshold for drop action:
```
./ip2drop.py -t 1
```

Show DB entries:
```
./ip2drop.py -p
```

ip2drop info:
```
./ip2drop.py -pc
```

Get statistic:
```
./ip2drop.py -s -t 1
```

Delete IP from DB:
```
./ip2drop.py -d '1.1.1.1'
```

## Running intervals

`cron` it is a good choise for `ip2drop`, as example you can use `/etc/cron.daily` or just `crontab`:

```
0 */1 * * * /path/to/ip2drop/ip2drop.py -c "cat /var/log/nginx/access.log | grep 'yii2.*301' | awk '{print $1}'" -l nginx.log -t 3 > /dev/null
```

## Logs

`ip2drop` using `logger` for own logging routines, log default located in `/var/log/ip2drop.log`:
```
30-01-2023 19-43-59,316 root INFO ip2drop started with params:
30-01-2023 19-43-59,316 root INFO Command: journalctl -u ssh -S today --no-tail | grep 'Failed password' Log: /opt/ip2drop/logs/ip2drop.log Threshold 150 Stat: False
30-01-2023 19-43-59,331 root INFO Processing log: /opt/ip2drop/logs/ip2drop.log
```
`ip2drop` automatically detects OS distro Linux/macOS, `ip2drop.log` location depends on OS:

* Linux: `/var/log/ip2drop.log`
* macOS: `<ip2drop location>/logs/ip2drop-script.log`

## Linux Logrotate

You can install `logrotate` rules for `ip2drop`, from `src/logrotate.d` catalog.

Copy `src/logrotate.d/ip2drop` to `/etc/logrotate.d/`:
```shell
cp src/logrotate.d/ip2drop /etc/logrotate.d/
```

# Option Requirements

* `python3`
* `ipset`
* `python3-pip`
* `python3-psutil`
* `python3-requests`
* `firewalld`

Tested and works on Debian 11+

Installation:
```shell
apt -y install python3 python3-pip python3-psutil python3-requests firewalld ipset
```

or just run `check-modules.sh` from `helpers` catalog.

# Remote server

You can user remote [cactusd](https://github.com/m0zgen/cactusd) server as central server for collect, aggregate dropped IP and
distribution for another `ip2drop` endpoints.

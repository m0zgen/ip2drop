# ip2drop

Find malicious IP addresses and send it's to firewalld `drop` zone for relaxing)

It is a interval-based solution, you can setup execute commands, threshold and running intervals.

## Parameters

* `-c` - command execution. Bash or another command which `ip2drop` will run
* `-l` - log file name. `ip2drop` will export IP addresses from this log file and this IP on threshold exceeding
* `-t` - threshold. Threshold exceeding value. Example: failure root login attempts through ssh max threshold - `1` 

Works with several conditions:

* Run exporter for exporting log file from `command` argument 
* Check exported log 
* If threshold value will exceed this IP will send to firewalld `drop` zone

## Example

```
./ip2drop.py -l ssh-ctl.log -t 1 -c "journalctl -u ssh -S today --no-tail | grep 'Connection closed by authenticating user root'"
```

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

## Running intervals

`cron` it is a good choise for `ip2drop`, as example you can use `/etc/cron.daily` or just `crontab`:

```
0 */1 * * * /path/to/ip2drop/ip2drop.py -c "cat /var/log/nginx/access.log | grep wp-content | awk '{print $1}'" -l nginx.log -t 10 > /dev/null
```

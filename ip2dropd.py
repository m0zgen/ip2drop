# Initial file for multithreading daemon
import datetime
import time
import daemon


def main_routine():
    while True:
        with open('/tmp/echo.txt', 'a') as fh:
            fh.write("{}\n".format(datetime.datetime.now()))
        time.sleep(1)


def main():
    with daemon.DaemonContext():
        main_routine()


# Init starter
if __name__ == "__main__":
    raise SystemExit(main())

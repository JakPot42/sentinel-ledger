#!/usr/bin/env python3
"""An independent clock log, for telling a stalled recorder from a stalled machine.

It shares no code with the recorder and does nothing but this: every 100 ms it reads the
wall clock, the monotonic clock and the boot-time clock, and writes one line:

    wall_seconds monotonic_seconds boottime_seconds late_ms

`late_ms` is how much later than planned this pass woke. On a healthy machine every line
is about 100 ms after the one before on all three clocks. If the whole machine pauses,
this process pauses with it, and the next line shows the jump. A wall clock that jumps
while the monotonic clock does not is a clock correction, not a pause.

Write the file somewhere that does not touch the disk (for example /dev/shm), so that a
slow disk cannot be mistaken for a paused machine.

    python3 clock_watchdog.py /dev/shm/watchdog.log
"""
import sys
import time

PERIOD = 0.1


def main():
    path = sys.argv[1]
    with open(path, "a", buffering=1) as out:
        due = time.monotonic()
        while True:
            wall = time.time()
            mono = time.clock_gettime(time.CLOCK_MONOTONIC)
            boot = time.clock_gettime(time.CLOCK_BOOTTIME)
            out.write("%.6f %.6f %.6f %.1f\n" % (wall, mono, boot, (time.monotonic() - due) * 1000))
            due += PERIOD
            now = time.monotonic()
            if due < now:
                # After a pause, carry on from now instead of firing a burst to catch up.
                due = now + PERIOD
            time.sleep(due - now)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass

#!/usr/bin/env python3
"""Combine logs from multiple bitcoin nodes as well as the test_framework log.

This streams the combined log output to stdout. Use combine_logs.py > outputfile to write to an outputfile.
"""

import argparse
from collections import defaultdict, namedtuple
import glob
import heapq
import os
import re
import sys

# Matches on the date format at the start of the log event
timestamp_pattern = re.compile(r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{6}")
# timestamp_pattern = re.compile(r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}")

LogEvent = namedtuple('LogEvent', ['timestamp', 'source', 'event'])

def main():

    parser = argparse.ArgumentParser(usage='%(prog)s [options] <test temporary directory>', description=__doc__)
    parser.add_argument('-c', '--color', dest = 'color', action='store_true', help='outputs the combined log with events colored by source (requires posix terminal colors. Use less -r for viewing)')
    parser.add_argument('--html', dest = 'html', action='store_true', help='outputs the combined log as html. Requires jinja2. pip install jinja2')
    args, unknown_args = parser.parse_known_args()

    if args.color and os.name != 'posix':
        print("color output requires posix terminal colors.")
        sys.exit(1)

    if args.html and args.color:
        print("Only one out of --color or --html should be specified")
        sys.exit(1)

    # There should only be one unknown argument - the path of the temporary test directory
    if len(unknown_args) != 1:
        print("Unexpected arguments" + str(unknown_args))
        sys.exit(1)

    log_events = read_logs(unknown_args[0])

    print_logs(log_events, color=args.color, html=args.html)

def read_logs(tmp_dir):

    files = [("test", "%s/test_framework.log" % tmp_dir)]
    for i,f in enumerate(glob.glob("%s/node*/regtest/debug.log" % tmp_dir)):
        files.append(("node%d" % i, f))

    return(heapq.merge(*[get_log_events(source, f) for source, f in files]))

def get_log_events(source, f):
    try:
        with open(f, 'r') as infile:
            event = ''
            timestamp = ''
            for line in infile:
                # skip blank lines
                if line == '\n': continue
                # if this line has a timestamp, it's the start of a new log event.
                t = timestamp_pattern.match(line)
                if t:
                    if event:
                        yield LogEvent(timestamp=timestamp, source=source, event=event.rstrip())
                    event = line
                    timestamp = t.group()
                # if it doesn't have a timestamp, it's a continuation line of the previous log.
                else:
                    event += "\n" + line
            # Flush the final event
            yield LogEvent(timestamp=timestamp, source=source, event=event.rstrip())
    except FileNotFoundError:
        print("File %s could not be opened. Continuing without it." % f, file=sys.stderr)


def print_logs(log_events, color = False, html = False):
    if not html:
        colors = defaultdict(lambda: '')
        if color:
            colors["test"]  = "\033[0;36m" #CYAN
            colors["node0"] = "\033[0;34m" #BLUE
            colors["node1"] = "\033[0;32m" #GREEN
            colors["node2"] = "\033[0;31m" #RED
            colors["node3"] = "\033[0;33m" #YELLOW
            colors["reset"] = "\033[0;0m"  #WHITE

        for event in log_events:
            print("{0} {1: <5} {2} {3}".format(colors[event.source.rstrip()], event.source, event.event, colors["reset"]))

    else:
        try:
            import jinja2
        except:
            print("jinja2 not found. Try `pip install jinja2`")
            sys.exit(1)
        env = jinja2.Environment(loader=jinja2.FileSystemLoader('./'))
        result = env.get_template('combined_log_template.html').render(title="Combined Logs from testcase", log_events = [event._asdict() for event in log_events])
        print(result)

if __name__ == '__main__':
    main()

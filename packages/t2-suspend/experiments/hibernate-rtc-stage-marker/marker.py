#!/usr/bin/python3
"""Decode an opt-in T2 hibernation RTC breadcrumb from the next boot log."""

import argparse
import json
import re


FILE = b"mba-t2-hibernate-rtc-stage-v1"
LINE = 1
FILEHASH = 997
DEVICEHASH = 1009
STAGES = {
  0: "armed-before-hibernate",
  1: "hibernate-entered",
  2: "snapshot-returned-image-write-entered",
  3: "image-write-returned-platform-entry-started",
  4: "acpi-s4-entry-started",
}


def file_hash():
  value = LINE
  for character in FILE:
    value = ((value << 16) + (value << 6) - value + character) & 0xFFFFFFFF
  return value % FILEHASH


def decode(magic):
  if re.fullmatch(r"\d+:\d+:\d+", magic) is None:
    raise ValueError("PM trace magic must have three decimal fields")
  user, source, device = map(int, magic.split(":"))
  matched = user in STAGES and source == file_hash() and 0 <= device < DEVICEHASH
  return {
    "magic": magic,
    "marker_file_hash": file_hash(),
    "recognized": matched,
    "stage": STAGES[user] if matched else None,
    "caution": "RTC hashes are not attempt identities; match the boot-bound guard and a pre-attempt baseline before attributing a marker" if matched else None,
  }


def magic_from_rtc(date, time):
  if re.fullmatch(r"\d{4}-\d{2}-\d{2}", date) is None or re.fullmatch(r"\d{2}:\d{2}:\d{2}", time) is None:
    raise ValueError("RTC date/time must use YYYY-MM-DD and HH:MM:SS")
  year, month, day = map(int, date.split("-"))
  hour, minute, _second = map(int, time.split(":"))
  if not (1 <= month <= 12 and 1 <= day <= 28 and 0 <= hour < 24 and 0 <= minute < 60 and minute % 3 == 0):
    raise ValueError("RTC date/time is outside the PM-trace encoding range")
  value = (year % 100) + (month - 1) * 100 + (day - 1) * 1200 + hour * 33600 + (minute // 3) * 806400
  user = value % 16
  value //= 16
  source = value % FILEHASH
  device = value // FILEHASH
  return f"{user}:{source}:{device}"


def main():
  parser = argparse.ArgumentParser(description=__doc__)
  parser.add_argument("--magic", help="The user:file:device fields from the next boot's PM: Magic number")
  parser.add_argument("--rtc-date", help="Current raw /sys/class/rtc/rtc0/date")
  parser.add_argument("--rtc-time", help="Current raw /sys/class/rtc/rtc0/time")
  arguments = parser.parse_args()
  try:
    if arguments.magic and not (arguments.rtc_date or arguments.rtc_time):
      magic = arguments.magic
    elif not arguments.magic and arguments.rtc_date and arguments.rtc_time:
      magic = magic_from_rtc(arguments.rtc_date, arguments.rtc_time)
    else:
      raise ValueError("Supply --magic or both --rtc-date and --rtc-time")
    result = decode(magic)
  except ValueError as error:
    parser.error(str(error))
  print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
  main()

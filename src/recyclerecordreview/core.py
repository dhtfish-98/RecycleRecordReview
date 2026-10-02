import argparse
import hashlib
import json
import os
import stat
import struct

MAX_BYTES = 16 * 1024 * 1024
MAX_RECORDS = 100000


class Invalid(ValueError):
    pass


class Unsupported(ValueError):
    pass


def require(ok, code):
    if not ok:
        raise Invalid(code)


def unpack(fmt, data, offset=0):
    require(
        offset >= 0 and offset + struct.calcsize(fmt) <= len(data), "truncated_field"
    )
    return struct.unpack_from(fmt, data, offset)


def text(data, encoding="utf-8"):
    try:
        return data.decode(encoding)
    except UnicodeError:
        raise Invalid("invalid_text_encoding") from None


def inspect(data):
    if not isinstance(data, bytes):
        raise TypeError("input must be bytes")
    digest = hashlib.sha256(data).hexdigest()
    try:
        require(len(data) <= MAX_BYTES, "input_limit")
        result = analyze(data)
        result.setdefault("status", "PASS")
        result.setdefault("complete", result["status"] == "PASS")
        result.setdefault("findings", [])
    except Unsupported as exc:
        result = {"status": "OPEN", "complete": False, "findings": [str(exc)]}
    except Invalid as exc:
        result = {"status": "FAIL", "complete": False, "findings": [str(exc)]}
    result.update(
        {
            "input_sha256": digest,
            "input_bytes": len(data),
            "claim": "Recorded format checks only; no authenticity, runtime or CVP approval conclusion.",
        }
    )
    return result


def read_local(path):
    fd = os.open(
        path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    )
    try:
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode), "regular_file_required")
        require(info.st_size <= MAX_BYTES, "input_limit")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            data = stream.read(MAX_BYTES + 1)
        require(len(data) <= MAX_BYTES, "input_limit")
        after = os.fstat(fd)
        require(
            (info.st_size, info.st_mtime_ns, info.st_ino)
            == (after.st_size, after.st_mtime_ns, after.st_ino),
            "input_changed_during_read",
        )
        return data
    finally:
        os.close(fd)


def main():
    parser = argparse.ArgumentParser(
        description="Read an explicitly supplied local evidence file and print a private-safe JSON report."
    )
    parser.add_argument("input")
    args = parser.parse_args()
    try:
        report = inspect(read_local(args.input))
    except (OSError, Invalid):
        report = {
            "status": "FAIL",
            "complete": False,
            "findings": ["input_read_failed"],
        }
    print(json.dumps(report, sort_keys=True, ensure_ascii=True))
    return {"PASS": 0, "FAIL": 1, "OPEN": 2}[report["status"]]


from datetime import datetime, timedelta, timezone


def analyze(data):
    version, size, timestamp = unpack("<QQQ", data)
    if version not in (1, 2):
        raise Unsupported("unsupported_recycle_record_version")
    if version == 1:
        require(len(data) == 544, "v1_record_length")
        raw = data[24:]
        count = 260
    else:
        (count,) = unpack("<I", data, 24)
        require(1 <= count <= 32768, "path_length_limit")
        require(len(data) == 28 + 2 * count, "v2_record_length")
        raw = data[28:]
    path = text(raw, "utf-16-le")
    require("\0" in path, "path_missing_terminator")
    end = path.index("\0")
    require(end > 0 and not path[end:].strip("\0"), "path_trailing_data")
    path = path[:end]
    require(not any(ord(c) < 32 for c in path), "path_control_character")
    require(timestamp > 0, "missing_deletion_timestamp")
    try:
        when = datetime(1601, 1, 1, tzinfo=timezone.utc) + timedelta(
            microseconds=timestamp // 10
        )
    except OverflowError:
        raise Invalid("timestamp_out_of_range") from None
    return {
        "records": [
            {
                "offset": 0,
                "version": version,
                "declared_size": size,
                "deletion_time_utc": when.isoformat(),
                "path_characters": len(path),
                "path_is_absolute": path.startswith(("\\", "/"))
                or (len(path) > 2 and path[1:3] == ":\\"),
            }
        ],
        "scope": "Isolated $I v1/v2 record; no $R lookup, recovery or authenticity inference.",
    }

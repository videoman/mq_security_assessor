#!/usr/bin/env python3
"""
IBM MQ security posture checks using the official ibmmq (mq-mqi-python) bindings.

Prerequisites:
  - IBM MQ client (C runtime + SDK), typically under /opt/mqm on Linux/macOS.
  - pip install ibmmq
  - For library load issues, run setmqenv or set LD_LIBRARY_PATH / DYLD_LIBRARY_PATH.

This tool is intended only for systems you own or are explicitly authorized to test.
Cleartext passwords are not retrievable from a correctly configured queue manager; this
script records identity and CHLAUTH metadata, and runs optional channel probes and
credential checks (built-in defaults plus optional files).
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import re
import sys
import traceback
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

try:
    import ibmmq as mq
    from ibmmq import CMQC
except ImportError as exc:  # pragma: no cover - runtime guard
    print(
        "Failed to import ibmmq. Install IBM MQ client libraries, then: pip install ibmmq\n"
        "Details: https://github.com/ibm-messaging/mq-mqi-python",
        file=sys.stderr,
    )
    raise SystemExit(1) from exc

_MQRC_NOT_AUTHORIZED = getattr(CMQC, "MQRC_NOT_AUTHORIZED", 2035)

# Common IBM MQ sample / tutorial / weak SVRCONN-style names (authorized testing only).
DEFAULT_SVRCONN_CHANNELS: tuple[str, ...] = (
    "SYSTEM.DEF.SVRCONN",
    "SYSTEM.ADMIN.SVRCONN",
    "SYSTEM.AUTO.SVRCONN",
    "DEV.APP.SVRCONN",
    "DEV.ADMIN.SVRCONN",
    "DEV.WMQ.SVRCONN",
    "WMQ.SVRCONN",
    "MQ.SVRCONN",
    "ADMIN.SVRCONN",
    "APP.SVRCONN",
    "CLIENT.SVRCONN",
    "CLIENT.CHANNEL",
    "MY.SVRCONN",
    "QM1.SVRCONN",
    "DEFAULT.SVRCONN",
    "CONNECTIONS",
    "GUEST.SVRCONN",
    "IBM.APP.SVRCONN",
    "CLOUD.APP.SVRCONN",
)

# Typical IBM developer image / lab defaults (not exhaustive).
DEFAULT_CREDENTIAL_PAIRS: tuple[tuple[str, str], ...] = (
    ("app", "password"),
    ("admin", "password"),
    ("admin", "passw0rd"),
    ("mqm", "mqm"),
    ("mqm", ""),
    ("mqm", "password"),
    ("mqadmin", "mqadmin"),
    ("mqadmin", "mqadmin!"),
    ("mqadmin", "passw0rd"),
    ("admin", "admin"),
    ("guest", "guest"),
    ("root", "root"),
    ("mquser", "mquser"),
    ("user", "user"),
)


@dataclass
class Target:
    host: str
    port: int


@dataclass
class RunConfig:
    targets_path: Path
    output_dir: Path
    queue_manager: str
    channel: str
    user: Optional[str]
    password: Optional[str]
    channel_pattern: str
    queue_pattern: str
    queue_types: list[int]
    message_queue: Optional[str]
    message_ops: list[str]
    message_limit: int
    save_dir: Path
    spray_creds_path: Optional[Path]
    channels_file: Optional[Path]
    use_default_channels: bool
    probe_channels: bool
    use_default_creds: bool
    credential_spray_enabled: bool
    start_service: Optional[str]
    acknowledge_service_risk: bool


def parse_targets(path: Path) -> list[Target]:
    out: list[Target] = []
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if "#" in line:
            line = line.split("#", 1)[0].strip()
        if ":" not in line:
            raise ValueError(f"Invalid target line (expected host:port): {raw!r}")
        host, port_s = line.rsplit(":", 1)
        host = host.strip()
        port = int(port_s.strip())
        out.append(Target(host=host, port=port))
    return out


def safe_report_basename(host: str, port: int) -> str:
    safe = re.sub(r"[^A-Za-z0-9._-]+", "_", f"{host}_{port}")
    return f"{safe}.txt"


def fmt_exc(e: BaseException) -> str:
    return "".join(traceback.format_exception_only(type(e), e)).strip()


def to_jsonable(obj: Any) -> Any:
    if obj is None or isinstance(obj, (bool, int, float, str)):
        return obj
    if isinstance(obj, bytes):
        try:
            return mq.to_string(obj)
        except Exception:
            return repr(obj)
    if isinstance(obj, dict):
        return {str(to_jsonable(k)): to_jsonable(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [to_jsonable(x) for x in obj]
    return repr(obj)


def connect_qmgr(
    queue_manager: str,
    channel: str,
    conn_info: str,
    user: Optional[str],
    password: Optional[str],
):
    if user and password:
        csp = mq.CSP()
        csp.CSPUserId = user
        csp.CSPPassword = password
        return mq.connect(queue_manager, channel, conn_info, csp=csp)
    if user or password:
        raise ValueError("Both user and password are required when using CSP credentials.")
    return mq.connect(queue_manager, channel, conn_info)


def qmgr_version_block(qmgr) -> dict[str, Any]:
    selectors = [CMQC.MQCA_VERSION, CMQC.MQIA_COMMAND_LEVEL, CMQC.MQCA_Q_MGR_NAME]
    attrs = qmgr.inquire(selectors)
    return {str(k): to_jsonable(v) for k, v in attrs.items()}


def enumerate_channels(pcf: mq.PCFExecute, pattern: str) -> list[dict[str, Any]]:
    args = {mq.CMQCFC.MQCACH_CHANNEL_NAME: pattern}
    try:
        response = pcf.MQCMD_INQUIRE_CHANNEL(args)
    except mq.MQMIError as e:
        if e.comp == CMQC.MQCC_FAILED and e.reason == CMQC.MQRC_UNKNOWN_OBJECT_NAME:
            return []
        raise
    rows: list[dict[str, Any]] = []
    for ch in response:
        rows.append({str(k): to_jsonable(v) for k, v in ch.items()})
    return rows


def enumerate_queues(pcf: mq.PCFExecute, pattern: str, queue_types: list[int]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for qtype in queue_types:
        name_attrs: list = [
            mq.CFST(Parameter=CMQC.MQCA_Q_NAME, String=pattern),
            mq.CFIN(Parameter=CMQC.MQIA_Q_TYPE, Value=qtype),
        ]
        try:
            response = pcf.MQCMD_INQUIRE_Q(name_attrs)
        except mq.MQMIError as e:
            if e.comp == CMQC.MQCC_FAILED and e.reason == CMQC.MQRC_UNKNOWN_OBJECT_NAME:
                continue
            raise
        for q in response:
            rows.append({str(k): to_jsonable(v) for k, v in q.items()})
    return rows


def enumerate_connections(pcf: mq.PCFExecute) -> list[dict[str, Any]]:
    args_name = {mq.CMQCFC.MQBACF_GENERIC_CONNECTION_ID: mq.ByteString("")}
    try:
        response = pcf.MQCMD_INQUIRE_CONNECTION(args_name)
    except mq.MQMIError as e:
        if e.comp == CMQC.MQCC_FAILED and getattr(e, "reason", None) == mq.CMQCFC.MQRCCF_CONNECTION_ID_ERROR:
            return []
        raise
    rows: list[dict[str, Any]] = []
    for c in response:
        rows.append({str(k): to_jsonable(v) for k, v in c.items()})
    return rows


def enumerate_chlauth(pcf: mq.PCFExecute, channel_wildcard: str = "*") -> list[dict[str, Any]]:
    args = {mq.CMQCFC.MQCACH_CHANNEL_NAME: channel_wildcard}
    try:
        response = pcf.MQCMD_INQUIRE_CHLAUTH_RECS(args)
    except mq.MQMIError as e:
        if e.comp == CMQC.MQCC_FAILED and e.reason in (
            CMQC.MQRC_UNKNOWN_OBJECT_NAME,
            _MQRC_NOT_AUTHORIZED,
        ):
            return []
        raise
    rows: list[dict[str, Any]] = []
    for r in response:
        rows.append({str(k): to_jsonable(v) for k, v in r.items()})
    return rows


def enumerate_services(pcf: mq.PCFExecute, pattern: str = "*") -> list[dict[str, Any]]:
    # MQCA_SERVICE_NAME is the usual selector for Inquire Service.
    key = getattr(CMQC, "MQCA_SERVICE_NAME", None)
    if key is None:
        return [{"error": "MQCA_SERVICE_NAME constant not found in this ibmmq build"}]
    args = {key: pattern}
    try:
        response = pcf.MQCMD_INQUIRE_SERVICE(args)
    except mq.MQMIError as e:
        if e.comp == CMQC.MQCC_FAILED and e.reason == CMQC.MQRC_UNKNOWN_OBJECT_NAME:
            return []
        raise
    rows: list[dict[str, Any]] = []
    for s in response:
        rows.append({str(k): to_jsonable(v) for k, v in s.items()})
    return rows


def start_service_probe(pcf: mq.PCFExecute, service_name: str) -> dict[str, Any]:
    key = getattr(CMQC, "MQCA_SERVICE_NAME", None)
    if key is None:
        return {"skipped": True, "reason": "MQCA_SERVICE_NAME not available"}
    args = {key: service_name}
    try:
        pcf.MQCMD_START_SERVICE(args)
    except mq.MQMIError as e:
        return {"ok": False, "comp": e.comp, "reason": e.reason, "detail": fmt_exc(e)}
    return {"ok": True, "service": service_name}


def sniff_messages(
    qmgr,
    queue_name: str,
    limit: int,
) -> list[dict[str, Any]]:
    od = mq.OD()
    od.ObjectName = queue_name
    q = mq.Queue(qmgr, od, CMQC.MQOO_BROWSE)
    gmo = mq.GMO()
    gmo.Options = CMQC.MQGMO_BROWSE_FIRST
    out: list[dict[str, Any]] = []
    for _ in range(limit):
        md = mq.MD()
        try:
            body = q.get(None, md, gmo)
        except mq.MQMIError as e:
            if e.reason == CMQC.MQRC_NO_MSG_AVAILABLE:
                break
            q.close()
            raise
        gmo.Options = CMQC.MQGMO_BROWSE_NEXT
        out.append(
            {
                "msg_id": to_jsonable(md.get("MsgId")),
                "correl_id": to_jsonable(md.get("CorrelId")),
                "format": to_jsonable(md.get("Format")),
                "put_date": to_jsonable(md.get("PutDate")),
                "put_time": to_jsonable(md.get("PutTime")),
                "length": len(body) if body is not None else 0,
                "preview": to_jsonable(body[:512] if isinstance(body, (bytes, bytearray)) else body),
            }
        )
    q.close()
    return out


def pop_messages(qmgr, queue_name: str, limit: int) -> list[dict[str, Any]]:
    q = mq.Queue(qmgr, queue_name)
    out: list[dict[str, Any]] = []
    for _ in range(limit):
        md = mq.MD()
        try:
            body = q.get(None, md)
        except mq.MQMIError as e:
            if e.reason == CMQC.MQRC_NO_MSG_AVAILABLE:
                break
            q.close()
            raise
        out.append(
            {
                "removed": True,
                "msg_id": to_jsonable(md.get("MsgId")),
                "correl_id": to_jsonable(md.get("CorrelId")),
                "length": len(body) if body is not None else 0,
                "preview": to_jsonable(body[:512] if isinstance(body, (bytes, bytearray)) else body),
            }
        )
    q.close()
    return out


def push_message(qmgr, queue_name: str, payload: str) -> dict[str, Any]:
    q = mq.Queue(qmgr, queue_name)
    q.put(payload)
    q.close()
    return {"put": True, "bytes": len(payload.encode("utf-8"))}


def dump_or_save_messages(
    qmgr,
    queue_name: str,
    limit: int,
    mode: str,
    save_dir: Path,
    host: str,
    port: int,
) -> list[dict[str, Any]]:
    """
    mode=dump: destructive get, include full body in report (truncation noted).
    mode=save: destructive get, write each message to save_dir as binary files.
    """
    q = mq.Queue(qmgr, queue_name)
    meta: list[dict[str, Any]] = []
    save_dir.mkdir(parents=True, exist_ok=True)
    stamp = dt.datetime.now(dt.UTC).strftime("%Y%m%dT%H%M%SZ")
    for i in range(limit):
        md = mq.MD()
        try:
            body = q.get(None, md)
        except mq.MQMIError as e:
            if e.reason == CMQC.MQRC_NO_MSG_AVAILABLE:
                break
            q.close()
            raise
        msg_id = md.get("MsgId")
        fname = f"{safe_report_basename(host, port)}_{stamp}_{i:04d}.bin"
        fpath = save_dir / fname
        if mode == "save":
            if isinstance(body, (bytes, bytearray)):
                fpath.write_bytes(body)
            else:
                fpath.write_bytes(str(body).encode("utf-8", errors="replace"))
            meta.append(
                {
                    "saved_path": str(fpath),
                    "msg_id": to_jsonable(msg_id),
                    "length": len(body) if body is not None else 0,
                }
            )
        else:
            if isinstance(body, (bytes, bytearray)):
                text = body.decode("utf-8", errors="replace")
            else:
                text = str(body)
            meta.append(
                {
                    "msg_id": to_jsonable(msg_id),
                    "length": len(text.encode("utf-8", errors="replace")),
                    "body": text[:200_000],
                    "truncated": len(text) > 200_000,
                }
            )
    q.close()
    return meta


def load_cred_pairs(path: Path) -> list[tuple[str, str]]:
    pairs: list[tuple[str, str]] = []
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if "#" in line:
            line = line.split("#", 1)[0].strip()
        if ":" not in line:
            continue
        u, p = line.split(":", 1)
        pairs.append((u.strip(), p.strip()))
    return pairs


def load_channel_names(path: Path) -> list[str]:
    names: list[str] = []
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if "#" in line:
            line = line.split("#", 1)[0].strip()
        if line:
            names.append(line)
    return names


def merge_channel_names(
    *,
    use_defaults: bool,
    channels_file: Optional[Path],
) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()

    def add(name: str) -> None:
        key = name.upper()
        if key in seen:
            return
        seen.add(key)
        out.append(name)

    if use_defaults:
        for ch in DEFAULT_SVRCONN_CHANNELS:
            add(ch)
    if channels_file is not None:
        for ch in load_channel_names(channels_file):
            add(ch)
    return out


def merge_cred_pairs(
    *,
    use_defaults: bool,
    creds_file: Optional[Path],
) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()

    def add_pair(user: str, password: str) -> None:
        key = (user, password)
        if key in seen:
            return
        seen.add(key)
        out.append(key)

    if use_defaults:
        for u, p in DEFAULT_CREDENTIAL_PAIRS:
            add_pair(u, p)
    if creds_file is not None:
        for u, p in load_cred_pairs(creds_file):
            add_pair(u, p)
    return out


def probe_channel_connect(
    queue_manager: str,
    conn_info: str,
    channel: str,
    user: Optional[str],
    password: Optional[str],
) -> dict[str, Any]:
    try:
        q = connect_qmgr(queue_manager, channel, conn_info, user, password)
        q.disconnect()
        return {"channel": channel, "ok": True}
    except mq.MQMIError as e:
        return {"channel": channel, "ok": False, "comp": e.comp, "reason": e.reason}
    except Exception as e:  # noqa: BLE001
        return {"channel": channel, "ok": False, "error": type(e).__name__, "detail": fmt_exc(e)}


def try_connect_with_creds(
    queue_manager: str,
    channel: str,
    conn_info: str,
    user: str,
    password: str,
) -> dict[str, Any]:
    try:
        q = connect_qmgr(queue_manager, channel, conn_info, user, password)
        q.disconnect()
        return {"user": user, "password_tried": "(redacted)", "ok": True}
    except mq.MQMIError as e:
        return {
            "user": user,
            "password_tried": "(redacted)",
            "ok": False,
            "comp": e.comp,
            "reason": e.reason,
        }
    except Exception as e:  # noqa: BLE001
        return {
            "user": user,
            "password_tried": "(redacted)",
            "ok": False,
            "error": type(e).__name__,
            "detail": fmt_exc(e),
        }


def assess_target(cfg: RunConfig, t: Target) -> dict[str, Any]:
    conn_info = f"{t.host}({t.port})"
    report: dict[str, Any] = {
        "target": {"host": t.host, "port": t.port, "conn_info": conn_info},
        "queue_manager": cfg.queue_manager,
        "channel": cfg.channel,
        "identity": {
            "note": "IBM MQ does not expose cleartext passwords over MQI/PCF. "
            "Review CHLAUTH records and optional credential spray results below.",
            "csp_user": cfg.user,
        },
        "timestamps": {"started": dt.datetime.now(dt.UTC).isoformat()},
    }

    merged_channels = merge_channel_names(
        use_defaults=cfg.use_default_channels,
        channels_file=cfg.channels_file,
    )
    report["channel_probe_settings"] = {
        "probe_enabled": cfg.probe_channels,
        "use_builtin_channel_list": cfg.use_default_channels,
        "channels_file": str(cfg.channels_file) if cfg.channels_file else None,
        "channels_to_try": len(merged_channels),
    }

    if cfg.probe_channels and merged_channels:
        report["channel_connection_probe"] = [
            probe_channel_connect(cfg.queue_manager, conn_info, ch, cfg.user, cfg.password)
            for ch in merged_channels
        ]
    else:
        report["channel_connection_probe"] = {
            "skipped": True,
            "reason": "Disabled or no channel names after merge (use defaults and/or --channels-file).",
        }

    cred_pairs = merge_cred_pairs(
        use_defaults=cfg.use_default_creds,
        creds_file=cfg.spray_creds_path,
    )
    report["credential_spray_settings"] = {
        "enabled": cfg.credential_spray_enabled,
        "use_builtin_pairs": cfg.use_default_creds,
        "creds_file": str(cfg.spray_creds_path) if cfg.spray_creds_path else None,
        "pairs_to_try": len(cred_pairs),
        "channel_used": cfg.channel,
    }

    if cfg.credential_spray_enabled and cred_pairs:
        report["credential_spray"] = [
            try_connect_with_creds(cfg.queue_manager, cfg.channel, conn_info, u, p) for u, p in cred_pairs
        ]
    else:
        report["credential_spray"] = {
            "skipped": True,
            "reason": "Disabled (--no-credential-spray) or no pairs (enable defaults and/or --spray-creds).",
        }

    qmgr = None
    try:
        qmgr = connect_qmgr(cfg.queue_manager, cfg.channel, conn_info, cfg.user, cfg.password)
        report["queue_manager_attributes"] = qmgr_version_block(qmgr)
        pcf = mq.PCFExecute(qmgr, response_wait_interval=30_000)

        report["channels"] = enumerate_channels(pcf, cfg.channel_pattern)
        report["queues"] = enumerate_queues(pcf, cfg.queue_pattern, cfg.queue_types)
        try:
            report["connections"] = enumerate_connections(pcf)
        except mq.MQMIError as e:
            report["connections"] = {
                "error": "MQMIError",
                "comp": e.comp,
                "reason": e.reason,
                "detail": fmt_exc(e),
            }
        except Exception as e:  # noqa: BLE001
            report["connections"] = {"error": type(e).__name__, "detail": fmt_exc(e)}
        report["chlauth_records"] = enumerate_chlauth(pcf, "*")
        report["services"] = enumerate_services(pcf, "*")

        if cfg.start_service:
            if not cfg.acknowledge_service_risk:
                report["start_service"] = {
                    "skipped": True,
                    "reason": "Refusing MQCMD_START_SERVICE without --i-accept-service-exec-risk",
                }
            else:
                report["start_service"] = start_service_probe(pcf, cfg.start_service)

        msg_section: dict[str, Any] = {}
        if cfg.message_queue and cfg.message_ops:
            for op in cfg.message_ops:
                key = op.strip().lower()
                if key == "sniff":
                    msg_section[key] = sniff_messages(qmgr, cfg.message_queue, cfg.message_limit)
                elif key == "pop":
                    msg_section[key] = pop_messages(qmgr, cfg.message_queue, cfg.message_limit)
                elif key == "push":
                    payload = os.environ.get("MQ_ASSESSOR_PUSH_BODY", "mq_security_assessor probe message")
                    msg_section[key] = push_message(qmgr, cfg.message_queue, payload)
                elif key == "dump":
                    msg_section[key] = dump_or_save_messages(
                        qmgr,
                        cfg.message_queue,
                        cfg.message_limit,
                        "dump",
                        cfg.save_dir,
                        t.host,
                        t.port,
                    )
                elif key in ("save",):
                    msg_section[key] = dump_or_save_messages(
                        qmgr,
                        cfg.message_queue,
                        cfg.message_limit,
                        "save",
                        cfg.save_dir,
                        t.host,
                        t.port,
                    )
                else:
                    msg_section[key] = {"error": f"Unknown message op {op!r}"}
        report["messages"] = msg_section
        report["primary_connection"] = {"ok": True, "channel": cfg.channel}
    except mq.MQMIError as e:
        report["primary_connection"] = {
            "ok": False,
            "comp": e.comp,
            "reason": e.reason,
            "detail": fmt_exc(e),
        }
    except Exception as e:  # noqa: BLE001
        report["primary_connection"] = {"ok": False, "error": type(e).__name__, "detail": fmt_exc(e)}
    finally:
        if qmgr is not None:
            try:
                qmgr.disconnect()
            except Exception:
                pass

    report["timestamps"]["finished"] = dt.datetime.now(dt.UTC).isoformat()
    return report


def render_text_report(data: dict[str, Any]) -> str:
    lines: list[str] = []
    lines.append("IBM MQ security assessment report")
    lines.append("=" * 72)
    lines.append(json.dumps(data, indent=2, sort_keys=True))
    lines.append("")
    lines.append("End of report.")
    return "\n".join(lines)


def queue_types_from_choice(choice: str) -> list[int]:
    if choice == "local":
        return [CMQC.MQQT_LOCAL]
    if choice == "remote":
        return [CMQC.MQQT_REMOTE]
    return [CMQC.MQQT_LOCAL, CMQC.MQQT_REMOTE]


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="IBM MQ assessment helper using ibmmq (mq-mqi-python).")
    p.add_argument("--targets", type=Path, required=True, help="File of host:port lines.")
    p.add_argument("--output-dir", type=Path, default=Path("reports"), help="Directory for per-host reports.")
    p.add_argument("--queue-manager", default=os.environ.get("MQ_QMGR", "QM1"))
    p.add_argument("--channel", default=os.environ.get("MQ_CHANNEL", "DEV.ADMIN.SVRCONN"))
    p.add_argument("--user", default=os.environ.get("MQ_USER"))
    p.add_argument("--password", default=os.environ.get("MQ_PASSWORD"))
    p.add_argument("--channel-pattern", default="*", help="PCF Inquire Channel name pattern.")
    p.add_argument("--queue-pattern", default="*", help="PCF Inquire Queue name pattern.")
    p.add_argument(
        "--queue-type",
        choices=("local", "remote", "all"),
        default="local",
        help="Queue type filter for PCF Inquire Queue.",
    )
    p.add_argument("--message-queue", help="Queue name for message operations.")
    p.add_argument(
        "--message-op",
        action="append",
        choices=("sniff", "pop", "push", "dump", "save"),
        help="Message operation (repeatable). destructive: pop, dump, save.",
    )
    p.add_argument("--message-limit", type=int, default=20)
    p.add_argument(
        "--save-dir",
        type=Path,
        default=Path("captured_messages"),
        help="Directory for binary captures when using save.",
    )
    p.add_argument(
        "--channels-file",
        type=Path,
        help="Extra channel names to try (one per line); merged with built-in defaults unless disabled.",
    )
    p.add_argument(
        "--no-default-channels",
        action="store_true",
        help="Do not use built-in channel name list; use only --channels-file (if set).",
    )
    p.add_argument(
        "--no-probe-channels",
        action="store_true",
        help="Skip trying each channel name for a client connection.",
    )
    p.add_argument(
        "--spray-creds",
        type=Path,
        help="File of user:password lines (password may contain ':'); merged with built-in default pairs unless disabled.",
    )
    p.add_argument(
        "--no-default-creds",
        action="store_true",
        help="Do not use built-in username:password pairs; use only --spray-creds file (if set).",
    )
    p.add_argument(
        "--no-credential-spray",
        action="store_true",
        help="Disable all credential connection attempts (built-in list and file).",
    )
    p.add_argument(
        "--start-service",
        help="If set, attempts MQCMD_START_SERVICE for this name (DANGEROUS: may execute server-side programs).",
    )
    p.add_argument(
        "--i-accept-service-exec-risk",
        action="store_true",
        help="Required alongside --start-service.",
    )
    return p


def main(argv: Optional[list[str]] = None) -> int:
    args = build_arg_parser().parse_args(argv)
    cfg = RunConfig(
        targets_path=args.targets,
        output_dir=args.output_dir,
        queue_manager=args.queue_manager,
        channel=args.channel,
        user=args.user,
        password=args.password,
        channel_pattern=args.channel_pattern,
        queue_pattern=args.queue_pattern,
        queue_types=queue_types_from_choice(args.queue_type),
        message_queue=args.message_queue,
        message_ops=list(args.message_op or []),
        message_limit=max(1, args.message_limit),
        save_dir=args.save_dir,
        spray_creds_path=args.spray_creds,
        channels_file=args.channels_file,
        use_default_channels=not args.no_default_channels,
        probe_channels=not args.no_probe_channels,
        use_default_creds=not args.no_default_creds,
        credential_spray_enabled=not args.no_credential_spray,
        start_service=args.start_service,
        acknowledge_service_risk=bool(args.i_accept_service_exec_risk),
    )

    targets = parse_targets(cfg.targets_path)
    cfg.output_dir.mkdir(parents=True, exist_ok=True)

    print("Authorized-use reminder: run only against queue managers you own or are permitted to test.")
    for t in targets:
        out_path = cfg.output_dir / safe_report_basename(t.host, t.port)
        print(f"Assessing {t.host}:{t.port} -> {out_path}")
        try:
            data = assess_target(cfg, t)
        except Exception as e:  # noqa: BLE001
            data = {
                "target": {"host": t.host, "port": t.port},
                "fatal": type(e).__name__,
                "detail": traceback.format_exc(),
            }
        out_path.write_text(render_text_report(data), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

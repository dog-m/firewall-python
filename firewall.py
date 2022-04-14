from datetime import datetime
from genericpath import exists, isfile
from http.client import FORBIDDEN
import io
import sys
from flask import Flask, json, render_template, request
from mitmproxy import ctx, http
from mitmproxy.addons import asgiapp
from mitmproxy.controller import DummyReply

import re
import json as js
from typing import *
import os


# ==============================================================================
# Activity logging
# ==============================================================================


class ActivityLogger:
    records: List[str]

    def __init__(self) -> None:
        self.records = []

    def clear(self):
        self.records.clear()

    def add(self, msg: str):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.records.append(f"{timestamp} | {msg}")

    def save(self):
        timestamp = datetime.now().strftime("%Y-%m-%d_%H.%M.%S")
        filename = f"./logs/{timestamp}.log"
        try:
            with open(filename, "wt") as file:
                file.writelines(self.records)
            self.clear()
        except:
            ctx.log.error("#######################")
            return ""


# ==============================================================================
# Rule IO and management
# ==============================================================================


def compile_url_expression(expression: str):
    """Only * (star) and . (dot) symbols are being handled."""
    chars: List[str] = []
    for c in expression:
        if c == ".":
            chars.append(r"\.")
        elif c == "*":
            chars.append(".*")
        else:
            chars.append(re.escape(c))
    pattern = "".join(chars)
    return re.compile(pattern, re.IGNORECASE)


DIR_RULES = "./rules"


class RuleDescription:
    class HostRecord:
        name: str
        allowing: Set[str]
        blocking: Set[str]

        def __init__(self, host_pattern: str, record_obj) -> None:
            self.name = host_pattern
            self.allowing = set(record_obj.get("allow", []))
            self.blocking = set(record_obj.get("block", []))
            if len(self.allowing) + len(self.blocking) == 0:
                raise RuntimeError(
                    f"No document rules have been specified for '{host_pattern}'"
                )

    id: str
    sites: Dict[str, HostRecord]

    def __init__(self, filename: str):
        with io.open(filename, "rt", encoding="utf-8") as file:
            obj = js.load(file)
            self.id = obj["id"]
            self.sites = dict()
            for host, record in obj["sites"].items():
                host_pattern = str(host)
                self.sites[host_pattern] = RuleDescription.HostRecord(
                    host_pattern, record
                )


class PathEntry:
    path: str
    refs: Set[RuleDescription]  # a list of rule IDs that refer to this path

    def __init__(self, path_expr: str) -> None:
        self.path = path_expr
        self.refs = set()
        self.path_pattern = compile_url_expression(path_expr)


class HostEntry:
    host: str
    # a list of paths(docs) that are allowed to be served to the user from this host
    allowed: Dict[str, PathEntry]
    blocked: Dict[str, PathEntry]

    def __init__(self, host_name: str) -> None:
        self.host = host_name
        self.allowed = dict()
        self.blocked = dict()
        self.host_pattern = compile_url_expression(host_name)


class RuleManager:
    loaded_descriptions: Dict[str, RuleDescription]
    hosts: Dict[str, HostEntry]
    active_rules: Set[str]

    def __init__(self) -> None:
        self.loaded_descriptions = dict()
        self.hosts = dict()
        self.active_rules = set()

    def load_rule(self, rule_id: str) -> None:
        # integrity workaround
        if rule_id in self.active_rules:
            raise RuntimeError(
                f"Unable to re-load active rule '{rule_id}'. Disable it first!"
            )

        filename = f"{DIR_RULES}/{rule_id}.json"
        rd = RuleDescription(filename)
        self.loaded_descriptions[rd.id] = rd

    def check(self, host: str, path: str) -> bool:
        allow = False
        block = True
        for h in self.hosts.values():
            if h.host_pattern.fullmatch(host):
                # look for blocking rule first
                block = self._check_path(path, h.blocked)
                if block:
                    break

                # perform "allowance" checks only if it's not already allowed
                if not allow:
                    allow = self._check_path(path, h.allowed)

        # block everything by default
        return allow and not block

    def _check_path(self, path, path_set) -> bool:
        for p in path_set.values():
            if p.path_pattern.fullmatch(path):
                return True
        return False

    def disable_all_rules(self) -> None:
        self.hosts.clear()
        self.active_rules.clear()

    def disable_rule(self, rule_id: str) -> None:
        # check is it loaded or not
        if rule_id in self.loaded_descriptions:
            rule = self.loaded_descriptions[rule_id]

            # check is it already have been disabled or not
            if rule_id in self.active_rules:
                self.active_rules.remove(rule_id)
                # ...
                for host_record in rule.sites.values():
                    host = self.hosts.get(host_record.name)
                    if host:
                        # ...
                        self._unreg_paths(host.allowed, host_record.allowing, rule)
                        self._unreg_paths(host.blocked, host_record.blocking, rule)
                    # remove empty host mappings
                    if len(host.allowed) + len(host.blocked) == 0:
                        del self.hosts[host_record.name]

    def _unreg_paths(
        self, nodes: Dict[str, PathEntry], paths: Set[str], rule: RuleDescription
    ) -> None:
        for path in paths:
            # ...
            entry = nodes.get(path)
            if entry:
                # reduce reference by one
                entry.refs.remove(rule)
                # none of the loaded rules references this path node, so it should be removed
                if len(entry.refs) == 0:
                    del nodes[path]

    def enable_rule_all(self, rules: List[str]):
        for rule_id in rules:
            self.enable_rule(rule_id)

    def enable_rule(self, rule_id: str) -> None:
        # check is it loaded or not
        if rule_id in self.loaded_descriptions:
            rule = self.loaded_descriptions[rule_id]

            # check is it already have been enabled or not
            if rule_id not in self.active_rules:
                self.active_rules.add(rule_id)
                # ...
                for host_record in rule.sites.values():
                    # make sure the host node exists
                    host = self.hosts.get(host_record.name)
                    if not host:
                        self.hosts[host_record.name] = host = HostEntry(
                            host_record.name
                        )
                    # ...
                    self._reg_paths(host.allowed, host_record.allowing, rule)
                    self._reg_paths(host.blocked, host_record.blocking, rule)

    def _reg_paths(
        self, nodes: Dict[str, PathEntry], paths: Set[str], rule: RuleDescription
    ) -> None:
        for path in paths:
            # ensure path/document entry exists
            entry = nodes.get(path)
            if not entry:
                nodes[path] = entry = PathEntry(path)
            # reference it
            entry.refs.add(rule)

    def rule_is_active(self, rule_id: str) -> bool:
        return rule_id in self.active_rules


# ==============================================================================
# General filtering functionality
# ==============================================================================


def load_text(filename: str) -> str:
    try:
        with io.open(filename, "rt", encoding="utf-8") as file:
            return "".join(file.readlines())
    except:
        ctx.log.error("#######################")
        return ""


class Firewall:
    block_message: bytes
    block_message_headers = {"Content-Type": "text/plain"}
    logger: ActivityLogger
    filter: RuleManager
    log_blocked_requests: bool = False

    def __init__(self) -> None:
        self.logger = ActivityLogger()
        self.filter = RuleManager()
        self.load_rules()
        # prepare blocked url message text
        self.block_message = str.encode(load_text("./PAGE_FORBIDDEN.txt"))

    def load_rules(self) -> None:
        # pre-load all rules
        for name in os.listdir(DIR_RULES):
            if name.endswith(".json"):
                self.filter.load_rule(name[:-5])

        # enable ones from the "config"
        with io.open("./config.json", "rt", encoding="utf-8") as file:
            config = js.load(file)
            for rule_id in config["startup-rules"]:
                self.filter.enable_rule(rule_id)

    def running(self):
        ctx.log.info("Firewall script has been loaded.")
        ctx.log.info(f"Python version: {sys.version}")

    def request(self, flow: http.HTTPFlow):
        # operate only on pure requests that haven't been taken by other plugins
        if flow.reply.state == "start":
            if self._is_allowed(flow.request):
                self._track_allowed(flow.request)
            else:
                self._block_request(flow)
                self._track_blocked(flow.request)

    def response(self, flow: http.HTTPFlow):
        pass

    def _is_allowed(self, request: http.Request) -> bool:
        return self.filter.check(request.host, request.path)

    def _block_request(self, flow: http.HTTPFlow) -> None:
        flow.reply.take()
        flow.response = http.Response.make(
            FORBIDDEN, self.block_message, self.block_message_headers
        )
        flow.reply.commit()

    def _track_allowed(self, request: http.Request) -> None:
        url = self.get_compact_url(request.url)
        # method = request.method
        self.logger.add(f"[+] {url}")

    def _track_blocked(self, request: http.Request) -> None:
        if self.log_blocked_requests:
            url = self.get_compact_url(request.url)
            self.logger.add(f"[#] {url}")

    def get_compact_url(self, url: str) -> str:
        params = url.find("?")
        if params != -1:
            return url[:params] + "?..."
        else:
            return url

    def reaupply_rules(self):
        pass


# ==============================================================================
# API and/or some sort of interfacing with the world
# ==============================================================================


def create_an_app(firewall: Firewall):
    app = Flask("Micro-Firewall")
    app.firewall = firewall

    @app.errorhandler(404)
    def nothing():
        """Default routing error handler"""

        return "", 404

    @app.get("/api/rules/list")
    def api_get_list_of_rules():
        """Returns lists of LOADED and ENABLED rules"""

        all = list(firewall.filter.loaded_descriptions.keys())
        all.sort()
        enabled = list(firewall.filter.active_rules)
        return {"all": all, "enabled": enabled}

    @app.put("/api/rules/set/enabled")
    def api_set_rule_enabled_or_not():
        """Enables ONLY specified set of rules (others will be disabled)"""

        # deactivate everything first
        firewall.filter.disable_all_rules()
        # leave only specified ones
        firewall.filter.enable_rule_all(request.args.getlist("rule"))
        # report with a set of active rules
        return {"enabled": list(firewall.filter.active_rules)}

    @app.get("/api/rules/check")
    def api_check_if_url_is_accessible():
        """Performs a check for a specified HOST and PATH over a set of currently ENABLED rules"""

        host = request.args["host"]
        path = request.args["path"]

        allow = {}
        block = {}

        def reg(rHost: HostEntry, rPath: PathEntry, target: dict):
            for rule in rPath.refs:
                ls = target.get(rule.id)
                if not ls:
                    target[rule.id] = ls = []
                ls.append(f"{rHost.host} => {rPath.path}")

        for h in firewall.filter.hosts.values():
            if h.host_pattern.fullmatch(host):
                # white
                for p in h.allowed.values():
                    if p.path_pattern.fullmatch(path):
                        reg(h, p, allow)
                # black
                for p in h.blocked.values():
                    if p.path_pattern.fullmatch(path):
                        reg(h, p, block)

        allowing = len(allow) > 0
        blocking = len(block) > 0

        return {
            "allow": allow,
            "block": block,
            "result": allowing and not blocking,
        }

    @app.get("/api/log/recent")
    def api_recent_records_from_log():
        """Returns last activity"""

        return {"records": firewall.logger.records}

    @app.put("/api/log/set/blocked")
    def api_toggle_logging_of_blocked_requests():
        """Enables or Disables logging of BLOCKED requests"""

        record = request.args.get("record", "False").lower()
        firewall.log_blocked_requests = record == "true" or record == "1"
        return {"log_blocked_requests": firewall.log_blocked_requests}

    @app.route("/")
    def main_page():
        """Main page / TODO"""
        return render_template("index.html")

    return app


class FirewallFrontend(asgiapp.WSGIApp):
    EXPECTED_HOST = re.compile(r"(localhost|127\.0\.0\.1)")

    def __init__(self, wsgi_app):
        super().__init__(wsgi_app, "127.0.0.1", 8080)

    def should_serve(self, flow: http.HTTPFlow) -> bool:
        return (
            self.EXPECTED_HOST.fullmatch(flow.request.host)
            and flow.reply.state == "start"
            # and not flow.error
            # and not flow.response
            # and not isinstance(flow.reply, DummyReply)
        )


def create_frontend(firewall: Firewall) -> FirewallFrontend:
    app = create_an_app(firewall)
    return FirewallFrontend(app)


# ==============================================================================
# Binding Firewall with Interface and plugin construction
# ==============================================================================


firewall = Firewall()
frontend = create_frontend(firewall)

addons = [frontend, firewall]

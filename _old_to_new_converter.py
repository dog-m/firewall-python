from configparser import ConfigParser
import json
from typing import Dict
import re


STRUCTURE = re.compile(r"(?P<host>.*) => (?P<url>.*)")


def add_rules(sites: Dict[str, Dict[str, str]], target: str) -> None:
    rules = ConfigParser()
    rules.read(f"./list_{target}.ini")
    
    for pattern in rules.sections():
        matcher = STRUCTURE.match(pattern)
        if not matcher:
            continue

        host_pattern = matcher.group("host")
        url_pattern = matcher.group("url")

        host = sites.get(host_pattern)
        if not host:
            sites[host_pattern] = host = {}

        host[target] = url_pattern


obj = {"sites": {}}

add_rules(obj["sites"], "allow")
add_rules(obj["sites"], "block")

print("================================")
print(json.dumps(obj, indent=4))

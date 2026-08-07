from bisect import bisect_right
from concurrent.futures import ThreadPoolExecutor
from functools import cache
from ipaddress import IPv4Address
from os import environ
from pathlib import Path
from threading import local

import requests


LOCATIONS = ("CN", "HK")
LIST_FILES = (Path("apple.list"), Path("openai.list"))
RANKING_LIMIT = 100
HISTORY_LIMIT = 100
WORKERS = 16

DIRECT_FILE = Path("direct.list")
PROXY_FILE = Path("proxy.list")

RADAR_URL = "https://api.cloudflare.com/client/v4/radar/ranking/top"
DOH_URL = "https://cloudflare-dns.com/dns-query"
APNIC_URL = "https://ftp.apnic.net/stats/apnic/delegated-apnic-latest"
FILTER_URL = "https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt"

RADAR_HEADERS = {"Authorization": f"Bearer {environ['CF_RADAR_TOKEN']}"}
DOH_HEADERS = {"Accept": "application/dns-json"}
EXCLUDED_SUFFIXES = tuple(f".{location.lower()}" for location in LOCATIONS)

A = 1
NS = 2
SOA = 6

_thread = local()
_cn_ranges = ()
_cn_starts = ()


def fetch(url, *, headers=None, params=None):
    if not hasattr(_thread, "session"):
        _thread.session = requests.Session()

    response = _thread.session.get(
        url,
        headers=headers,
        params=params,
        timeout=20,
    )
    response.raise_for_status()
    return response


def normalize_dns_name(domain):
    return domain.lower().rstrip(".")


def fetch_top_domains(location):
    data = fetch(
        RADAR_URL,
        headers=RADAR_HEADERS,
        params={
            "location": location,
            "limit": RANKING_LIMIT,
            "rankingType": "POPULAR",
        },
    ).json()

    return [
        item["domain"].lower()
        for item in data["result"]["top_0"]
    ]


def load_cn_ranges():
    global _cn_ranges, _cn_starts

    ranges = []

    for record in fetch(APNIC_URL).text.splitlines():
        fields = record.split("|")

        if (
            fields[:3] == ["apnic", "CN", "ipv4"]
            and fields[6] in ("allocated", "assigned")
        ):
            start = int(IPv4Address(fields[3]))
            ranges.append((
                start,
                start + int(fields[4]) - 1,
            ))

    _cn_ranges = tuple(sorted(ranges))
    _cn_starts = tuple(
        start
        for start, _ in _cn_ranges
    )


def locate_ip(ip):
    value = int(IPv4Address(ip))
    index = bisect_right(_cn_starts, value) - 1

    return (
        "CN"
        if index >= 0 and value <= _cn_ranges[index][1]
        else "OTHER"
    )


@cache
def query_dns(domain, record_type):
    return fetch(
        DOH_URL,
        headers=DOH_HEADERS,
        params={
            "name": domain,
            "type": record_type,
        },
    ).json()


@cache
def get_addresses(domain):
    return tuple(sorted({
        normalize_dns_name(record["data"])
        for record in query_dns(domain, "A").get("Answer", [])
        if record["type"] == A
    }))


@cache
def get_nameservers(domain):
    labels = domain.rstrip(".").split(".")

    for index in range(len(labels) - 1):
        data = query_dns(
            ".".join(labels[index:]),
            "NS",
        )
        nameservers = set()
        zone = None

        for record in data.get("Answer", []):
            if record["type"] == NS:
                nameservers.add(
                    normalize_dns_name(record["data"])
                )
                zone = (
                    zone
                    or normalize_dns_name(record["name"])
                )

        for record in data.get("Authority", []):
            if record["type"] == SOA:
                nameservers.add(
                    normalize_dns_name(
                        record["data"].split()[0]
                    )
                )
                zone = (
                    zone
                    or normalize_dns_name(record["name"])
                )

        if nameservers:
            return zone, tuple(sorted(nameservers))

    return None, ()


def trace_domain(
    domain,
    label,
    indent,
    visited,
):
    lines = [f"{indent}{label}"]

    for ip in get_addresses(domain):
        location = locate_ip(ip)
        lines.append(
            f"{indent}  A {ip} {location}"
        )

        if location == "CN":
            return True, lines

    zone, nameservers = get_nameservers(domain)

    if zone is None or zone in visited:
        return False, lines

    visited.add(zone)

    for nameserver in nameservers:
        found, branch = trace_domain(
            nameserver,
            f"NS {nameserver}",
            f"{indent}  ",
            visited,
        )
        lines.extend(branch)

        if found:
            return True, lines

    return False, lines


def classify_domain(domain):
    found, lines = trace_domain(
        domain,
        domain,
        "",
        set(),
    )

    return (
        domain,
        "CN" if found else "OTHER",
        lines,
    )


def load_list_domains():
    return {
        domain.strip().lower().removeprefix(".")
        for path in LIST_FILES
        for domain in path.read_text(
            encoding="utf-8"
        ).splitlines()
        if domain.strip()
    }


def load_filter_domains():
    return {
        rule[2:rule.index("^")].lower()
        for rule in fetch(FILTER_URL).text.splitlines()
        if rule.startswith("||") and "^" in rule
    }


def build_lists(
    scans,
    list_domains,
    filter_domains,
):
    results = []
    direct = []
    proxy = []

    for domain, location, _ in scans:
        fields = [location]

        if domain in list_domains:
            fields.append("LIST")

        if domain in filter_domains:
            fields.append("FILTER")

        results.append(
            f"{domain}:{','.join(fields)}"
        )

        if len(fields) == 1:
            target = (
                direct
                if location == "CN"
                else proxy
            )
            target.append(f".{domain}")

    return results, direct, proxy


def write_lines(path, lines):
    path.write_text(
        "\n".join((*lines, "")),
        encoding="utf-8",
    )


def update_history(
    path,
    current,
    pinned=(),
):
    previous = (
        line
        for line in path.read_text(
            encoding="utf-8"
        ).splitlines()
        if line
    )

    lines = list(dict.fromkeys((
        *pinned,
        *current,
        *previous,
    )))[:HISTORY_LIMIT]

    write_lines(path, lines)
    return lines


def main():
    with ThreadPoolExecutor(
        max_workers=WORKERS
    ) as executor:
        ranges_future = executor.submit(
            load_cn_ranges
        )
        filter_future = executor.submit(
            load_filter_domains
        )

        ranked = executor.map(
            fetch_top_domains,
            LOCATIONS,
        )

        domains = list(dict.fromkeys(
            domain
            for group in ranked
            for domain in group
            if not domain.endswith(
                EXCLUDED_SUFFIXES
            )
        ))

        ranges_future.result()

        scans = list(
            executor.map(
                classify_domain,
                domains,
            )
        )
        filter_domains = filter_future.result()

    results, direct, proxy = build_lists(
        scans,
        load_list_domains(),
        filter_domains,
    )

    direct = update_history(
        DIRECT_FILE,
        direct,
        (".cn",),
    )
    proxy = update_history(
        PROXY_FILE,
        proxy,
    )

    paths = []

    for _, _, lines in scans:
        paths.extend((*lines, ""))

    paths_output = "\n".join(paths).rstrip()
    results_output = "\n".join(results)
    cn_count = sum(
        location == "CN"
        for _, location, _ in scans
    )

    print(
        f"DNS paths:\n{paths_output}\n\n"
        f"Domain results:\n{results_output}\n\n"
        f"Summary: {len(results)} domains; "
        f"{cn_count} CN, "
        f"{len(results) - cn_count} OTHER; "
        f"{len(direct)} direct rules, "
        f"{len(proxy)} proxy rules."
    )


if __name__ == "__main__":
    main()

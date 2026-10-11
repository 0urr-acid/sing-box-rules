#!/usr/bin/python3
import argparse
import re
import sys
import time
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import urlopen
import tempfile
import ipaddress
import subprocess
import json
import logging

logger = logging.getLogger("compiler")
logger.setLevel(logging.DEBUG)
console_handler = logging.StreamHandler(sys.stdout)
console_handler.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
console_handler.setFormatter(formatter)
logger.addHandler(console_handler)

logger.info("Init pipeline")

BASE_DIR = Path(__file__).resolve().parent

parser = argparse.ArgumentParser(description="Описание вашей программы")

parser.add_argument(
    "-o", "--output",
    help="Result path",
    default=BASE_DIR / "output",
    required=False
)
parser.add_argument(
    "-e", "--exec",
    help="Executable",
    default="sing-box",
    required=False
)
parser.add_argument(
    "--debug",
    action="store_true",
    default=False,
    help="Debug mode",
    required=False,
)

args = parser.parse_args()

OUTPUT_DIR = Path(args.output)
OUTPUT_DIR_CHECK = OUTPUT_DIR / "check"
if not OUTPUT_DIR_CHECK.exists():
    OUTPUT_DIR_CHECK.mkdir(exist_ok=True, parents=True)
    logger.info(f"Output dir created: {OUTPUT_DIR}")

DEBUG_DIR = OUTPUT_DIR.parent / "output_debug"
if args.debug:
    DEBUG_DIR.mkdir(exist_ok=True)

CACHE_SRS_URL = {}
CACHE_SRS_FILENAMES = []


def run_sing_box(command: str):
    command_arr = command.split(" ")

    try:
        result = subprocess.run([args.exec] + command_arr, capture_output=True, check=True)
        return result.stdout.strip()

    except subprocess.CalledProcessError as e:
        return None


def is_ip(line):
    try:
        ipaddress.ip_network(line, strict=False)
        return True
    except Exception:
        return False


def is_domain(line):
    return line.count(".") > 1


def urlopen_part(url, retry=0):
    if retry >= 20:
        raise ConnectionError("Can't get file")

    try:
        with urlopen(url) as response:
            body = response.read()
        return body
    except HTTPError as e:
        if e.code == 429:
            wait = e.headers.get('Retry-After', 5)
            logger.info(f"Rate limited url = {url}! Waiting {wait} seconds...")
            time.sleep(int(wait))
            return urlopen_part(url, retry=retry + 1)


def get_list_text_format(url):
    logger.info(f"Download list: {url}")
    return urlopen_part(url).decode("utf-8").split("\n")


def get_list_adguard(url):
    logger.info(f"Download adguard rules: {url}")
    return urlopen_part(url).decode("utf-8")


def get_srs_file(url):
    if url in CACHE_SRS_URL:
        return CACHE_SRS_URL[url]

    og_file_name = url.split("/")[-1]
    iterator = 1

    file_name = og_file_name
    while file_name in CACHE_SRS_FILENAMES:
        file_split = og_file_name.split(".", maxsplit=1)
        file_name = file_split[0] + f"_{iterator}." + file_split[1]
        iterator += 1

    if not (args.debug and Path(OUTPUT_DIR_CHECK / file_name).exists()):
        logger.info(f"Downloading SRS file... {url}")
        downloaded_file = urlopen_part(url)
        if downloaded_file is None:
            raise URLError(f"Failed to download SRS file {url}")
        with open(OUTPUT_DIR_CHECK / file_name, "wb") as f:
            f.write(downloaded_file)

    CACHE_SRS_URL[url] = Path(OUTPUT_DIR_CHECK / file_name)
    CACHE_SRS_FILENAMES.append(file_name)

    logger.info(f"Downloaded srs file: {CACHE_SRS_URL[url]}")
    return CACHE_SRS_URL[url]


def normalize_domains(
    domains: list[str],
    domain_suffixes: list[str],
    domain_regex: list[str]
) -> tuple[list[str], list[str]]:
    compiled_regexes = [re.compile(r) for r in domain_regex if r]

    def is_regex_matched(val: str) -> bool:
        return any(rx.search(val) for rx in compiled_regexes)

    # 1. Предварительная очистка и фильтрация суффиксов по regex
    raw_suffixes = {
        s.lower().strip(".") for s in domain_suffixes if s and s.strip(".")
    }
    valid_suffixes = []
    for s in raw_suffixes:
        if not is_regex_matched(s):
            valid_suffixes.append(s)
        else:
            logger.info(f"Regex matched suffix: {s}")

    # 2. Нормализация domain_suffixes через Trie (удаление под-суффиксов)
    suffix_trie = {}
    for s in valid_suffixes:
        parts = s.split(".")[::-1]
        node = suffix_trie
        covered = False
        for part in parts:
            if None in node:
                covered = True
                break
            if part not in node:
                node[part] = {}
            node = node[part]
        if not covered:
            node.clear()
            node[None] = True

    # Собираем очищенные суффиксы из Trie
    norm_suffixes = []
    def collect_suffixes(node: dict, parts: list[str]):
        if None in node:
            _domain_suffix = ".".join(reversed(parts))
            if not _domain_suffix.count("."):
                _domain_suffix = "." + _domain_suffix
            norm_suffixes.append(_domain_suffix)
            return
        for part, child in node.items():
            parts.append(part)
            collect_suffixes(child, parts)
            parts.pop()

    collect_suffixes(suffix_trie, [])
    if args.debug and len(domain_suffixes) < 1000:
        for domain_suffix in domain_suffixes:
            if domain_suffix not in norm_suffixes:
                logger.info(f"Domain suffix normalized: {domain_suffix}")

    # Проверка перекрытия домена суффиксом из Trie
    def is_covered_by_suffix(domain: str) -> bool:
        parts = domain.split(".")[::-1]
        node = suffix_trie
        for part in parts:
            if None in node:
                return True
            if part not in node:
                return False
            node = node[part]
        return None in node

    # 3. Фильтрация domains (по regex и по Trie суффиксов)
    raw_domains = {
        d.lower().strip(".") for d in domains if d and d.strip(".")
    }
    norm_domains = []

    for d in raw_domains:
        if is_regex_matched(d):
            logger.info(f"Regex matched domain: {d}")
            continue
        if is_covered_by_suffix(d):
            logger.info(f"Domain suffix matched: {d}")
            continue
        norm_domains.append(d)

    return sorted(norm_domains), sorted(norm_suffixes)


def normalize_ip_ranges(values: list[str]) -> list[str]:
    # Отдельные trie для IPv4 и IPv6
    # Узел: [child0, child1, is_terminal]
    # is_terminal = True означает, что этот префикс покрывает всё поддерево

    def make_node():
        return [None, None, False]

    def insert(trie_root, network):
        addr_int = int(network.network_address)
        prefix = network.prefixlen
        max_bits = 32 if network.version == 4 else 128

        node = trie_root
        for i in range(max_bits - 1, max_bits - 1 - prefix, -1):
            if node[2]:
                # Уже покрыто более широкой сетью — выходим
                return
            bit = (addr_int >> i) & 1
            if node[bit] is None:
                node[bit] = make_node()
            node = node[bit]

        # Достигли нужной глубины — помечаем терминал и срезаем дочерние ветки
        node[2] = True
        node[0] = None
        node[1] = None

    def collect(node, addr_int, depth, max_bits, prefix_len, results):
        if node is None:
            return
        if node[2]:
            # Восстанавливаем сеть из накопленного addr_int и глубины
            shift = max_bits - prefix_len
            network_addr = addr_int << shift
            if max_bits == 32:
                net = ipaddress.ip_network(
                    (network_addr.to_bytes(4, 'big'), prefix_len), strict=False
                )
            else:
                net = ipaddress.ip_network(
                    (network_addr.to_bytes(16, 'big'), prefix_len), strict=False
                )
            results.append(str(net))
            return
        for bit in (0, 1):
            if node[bit] is not None:
                collect(node[bit], (addr_int << 1) | bit, depth + 1,
                        max_bits, prefix_len + 1, results)

    root4 = make_node()
    root6 = make_node()

    networks = [ipaddress.ip_network(v, strict=False) for v in values]

    # Сортируем: более короткие префиксы (широкие сети) вставляем первыми —
    # тогда они сразу срезают все вложенные при вставке
    networks.sort(key=lambda n: (n.version, n.prefixlen))

    for net in networks:
        root = root4 if net.version == 4 else root6
        insert(root, net)

    results4, results6 = [], []
    collect(root4, 0, 0, 32, 0, results4)
    collect(root6, 0, 0, 128, 0, results6)

    # Сортируем финальный список для стабильного вывода
    results4.sort(key=lambda s: ipaddress.ip_network(s).network_address)
    results6.sort(key=lambda s: ipaddress.ip_network(s).network_address)

    return results4 + results6


def process_line(line: str, ip_addresses, domains, adguard_lists, srs_files):
    line = line.split("#")[0].strip()

    if line.startswith(";;"):
        # Файл со списком доменов и ip, который мы качаем и сразу обрабатываем
        for line in get_list_text_format(line.split(";;")[1].strip()):
            process_line(line, ip_addresses, domains, adguard_lists, srs_files)
        return
    elif line.startswith("||"):
        adguard_lists.append(get_list_adguard(line.split("||")[1].strip()))
        return
    elif line.startswith("??") and line.rstrip().endswith(".srs"):
        srs_files.append(get_srs_file(line.split("??")[1].strip()))
        return

    if not line:
        return
    elif line.startswith("#"):
        return
    elif is_ip(line):
        if "/" not in line:
            line = line + "/32"
        ip_addresses.append(line)
    else:
        if line.startswith("www."):
            line = line.strip("www.")
        domains.append(line)


def get_rule(ip_addresses: list[str], domains: list[str], domain_suffixes: list[str], domain_regex: list[str]) -> list[str]:
    domain_rule_dict = {}
    ip_rule_dict = {}

    if len(ip_addresses) > 0:
        ip_rule_dict["ip_cidr"] = ip_addresses
    if len(domains) > 0:
        domain_rule_dict["domain"] = domains
    if len(domain_suffixes) > 0:
        domain_rule_dict["domain_suffix"] = domain_suffixes
    if len(domain_regex) > 0:
        domain_rule_dict["domain_regex"] = domain_regex

    ip_result_dict = {"version": 3, "rules": []}
    if len(ip_rule_dict) > 0:
        ip_result_dict["rules"].append(ip_rule_dict)
    domain_result_dict = {"version": 3, "rules": []}
    if len(domain_rule_dict) > 0:
        domain_result_dict["rules"].append(domain_rule_dict)

    return ip_result_dict, domain_result_dict


def generate_debug_rule(rule_name, rule):
    with open(DEBUG_DIR / rule_name, "w") as f:
        json.dump(rule, f, indent=2)


def parse_srs_files(srs_files: list[Path]):
    srs_ips, srs_domains, srs_domain_suffix, srs_domain_regex = [], [], [], []

    def list_append(_list, value):
        if isinstance(value, list):
            _list.extend(value)
        if isinstance(value, str):
            _list.append(value)

    for srs_file in srs_files:
        with tempfile.NamedTemporaryFile(delete=True, suffix=srs_file.stem + ".json") as tmp_file:
            run_sing_box(f"rule-set decompile {srs_file} -o {tmp_file.name}")

            rules = json.loads(tmp_file.read())

            for rule in rules["rules"]:
                if "ip_cidr" in rule:
                    list_append(srs_ips, rule["ip_cidr"])
                if "domain" in rule:
                    list_append(srs_domains, rule["domain"])
                if "domain_suffix" in rule:
                    list_append(srs_domain_suffix, rule["domain_suffix"])
                if "domain_regex" in rule:
                    list_append(srs_domain_regex, rule["domain_regex"])

    logger.info(f"Srs loaded: ips: {len(srs_ips)}, domains: {len(srs_domains)}, domain_suffix: {len(srs_domain_suffix)}, domain_regex: {len(srs_domain_regex)}")
    return srs_ips, srs_domains, srs_domain_suffix, srs_domain_regex


def generate_rule(rule_name, tmpdir, rule, adguard=False):
    if adguard:
        suffix = "r.txt"
        argument = "convert"
        argument_suffix = " -t adguard"
        result_file = OUTPUT_DIR / (rule_name + "-adguard.srs")
    else:
        suffix = "r.json"
        argument = "compile"
        argument_suffix = ""
        result_file = OUTPUT_DIR / (rule_name + ".srs")

    if args.debug and not adguard:
        generate_debug_rule(result_file.stem + ".json", rule)

    with tempfile.NamedTemporaryFile(dir=tmpdir, delete=True, suffix=suffix, prefix="rule_") as tmp_file:
        with open(tmp_file.name, "w") as f:
            if adguard:
                f.write(rule)
            else:
                json.dump(rule, f)

        run_sing_box(f"rule-set {argument} {tmp_file.name} -o {result_file}{argument_suffix}")
        logger.info(f"Created {result_file}{argument_suffix}")


def generate_rules(rule_name, domain_rules_dict, ip_rules_dict, adguard_lists):
    with tempfile.TemporaryDirectory() as tmpdir:
        logger.info(f"Tempdir created: {tmpdir}")
        generate_rule(rule_name, tmpdir, domain_rules_dict)
        generate_rule(rule_name + "-ip", tmpdir, ip_rules_dict)
        if len(adguard_lists) > 0:
            generate_rule(rule_name, tmpdir, "\n".join(adguard_lists), adguard=True)


def download_list(txt_file):
    with open(txt_file, "r") as f:
        while line := f.readline():
            line = line.split("#")[0].strip()
            if line:
                with open(OUTPUT_DIR / line.split("/")[-1], "wb") as f2:
                    f2.write(urlopen_part(line))


def process_txt_file(txt_file):
    logger.info(f"Processing {txt_file.stem}")

    ip_addresses = []
    domains = []
    adguard_lists = []
    srs_files = []

    with open(txt_file, "r") as f:
        while line := f.readline():
            process_line(line, ip_addresses, domains, adguard_lists, srs_files)
    logger.info(
        f"Raw {txt_file.stem}: found {len(ip_addresses)} ip, {len(domains)} domains, {len(adguard_lists)} adguard files.")

    return ip_addresses, domains, adguard_lists, srs_files


def process_dir(rule_dir):
    """
    Функция обрабатывает директорию с правилами.
    """

    logger.info(f"Processing {rule_dir.name}")

    dir_ip_addresses = []
    dir_domains = []
    dir_adguard_lists = []
    dir_srs_files = []

    for txt_file in rule_dir.glob("*.txt"):
        ip_addresses, domains, adguard_lists, srs_files = process_txt_file(txt_file)
        dir_ip_addresses.extend(ip_addresses)
        dir_domains.extend(domains)
        dir_adguard_lists.extend(adguard_lists)
        dir_srs_files.extend(srs_files)

    logger.info(
        f"Raw result {rule_dir.name}: found {len(dir_ip_addresses)} ip, {len(dir_domains)} domains, {len(dir_adguard_lists)} adguard files.")

    srs_ips, srs_domains, srs_domain_suffix, srs_domain_regex = parse_srs_files(srs_files)
    ip_addresses = normalize_ip_ranges(dir_ip_addresses + srs_ips)
    logger.info(f"Normalized: {len(ip_addresses)} ip")

    domains, domain_suffix = normalize_domains(srs_domains, srs_domain_suffix + dir_domains, srs_domain_regex)
    logger.info(f"Normalized: {len(domains)} domains, {len(domain_suffix)} suffix")

    ip_rules_dict, domain_rules_dict  = get_rule(ip_addresses, domains, domain_suffix, srs_domain_regex)

    generate_rules(rule_dir.name, domain_rules_dict, ip_rules_dict, dir_adguard_lists)


for file in (BASE_DIR / "rules").iterdir():
    if file.is_dir():
        process_dir(file)

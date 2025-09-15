import csv
import json
import functools
import itertools
import io
import argparse

from typing import Dict, List


class TransportParams:
    params: Dict[str, str]
    host: str

    def __init__(self, host: str, raw: str) -> None:
        self.host = host
        decoder = json.JSONDecoder(strict=False)
        self.params = decoder.decode(raw)

    def __repr__(self) -> str:
        return self.host + ": " + f"{self.params.keys()}"

def parse_raw_result(csvfile: io.TextIOWrapper, max_columns: int, host_column: int, target_column: int) -> List[tuple[str, str]]:
    results = []
    results_reader = csv.reader(csvfile, dialect='excel', quoting=csv.QUOTE_NONE)

    skip = True
    for row in results_reader:
        # Skip the header.
        if skip:
            skip = False
            continue

        host = row[host_column]

        if len(row) < max_columns:
            continue

        raw_json = row[max_columns]
        if len(row) > max_columns:
            def acc(existing: str, next: str) -> str:
                return f"{existing + "," if existing else ""} {next}"
            raw_json = functools.reduce(acc, row[max_columns:])

        if row[target_column] != 'NA':
            results.append((host, raw_json))
            pass
    return results

def main()-> None:

    parser = argparse.ArgumentParser(prog="tparams",
                                     description="Analysis of transport parameters captured during data collection")

    parser.add_argument('filename')
    parser.add_argument('fields', nargs='*')

    args = parser.parse_args()


    fields: List[str] = args.fields
    filename: str = args.filename

    raw_results: List[tuple[str, str]] = []

    with open(filename) as csvfile:
        raw_results = parse_raw_result(csvfile, 9, 2, 9)
    transport_params: List[TransportParams] = []
    for raw_result in raw_results:
        transport_params.append(TransportParams(*raw_result))

    def filter(current: TransportParams) -> str:
        result = f"{current.host}, "
        for field in fields:
            result += f"{current.params[field]},"
        return result

    print(f"host, " + ','.join(fields))
    for result in map(filter, transport_params):
        print(result)

main()

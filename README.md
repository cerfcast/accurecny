## Accurecny

A tool for determining whether a host supports Accurate ECN.

## Data

For information about data available from scans of the Internet
using this tool, please see [https://accurecny.cerfca.st/](https://accurecny.cerfca.st/).

## Using

### Collecting Data On Popular Websites

```bash
$ ./target/debug/accurecny -d -d -d --myip 0.0.0.0 --top-sites <path to data file> --output <path to results file> 2>&1 | tee today.out
```

> Note: The configuration for data collection (above) includes extra debugging output (`-d -d -d`) and stores that to a file named `today.out` using `tee`. 

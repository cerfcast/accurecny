---
layout: home
---

Accurecny (a play on _accuracy_ and _ECN_) began as a tool designed to measure the adoption of Accurate ECN on the Internet. Over time it has expanded into a tool for collecting data about the parameters of connections established between two Internet-connected endpoints over TCP and QUIC.

In addition to the tool itself, this website documents and hosts a set of longitudinal data that measures

- the deployment of Accurate ECN on the Internet, and
- the values of transport parameters for QUIC connections

to the top 500 most popular domain names on the Internet, according to Tranco ([see below](#the-data)).

**Latest Results:**

The latest set of longitudinal data were collected on September 22nd, 2025. See [The Data](#the-data) for all the details!

### What is Accurate ECN?

Far be it from me to answer this question. I'll let the experts describe it:

> Explicit Congestion Notification (ECN) is a mechanism where network nodes can mark IP packets instead of dropping them to indicate incipient congestion to the endpoints. ... ECN was originally specified for TCP in such a way that only one feedback signal can be transmitted per Round-Trip Time (RTT). Recent new TCP mechanisms like Congestion Exposure (ConEx), Data Center TCP (DCTCP) or Low Latency, Low Loss, and Scalable Throughput (L4S) need more accurate ECN feedback information whenever more than one marking is received in one RTT. This document updates the original ECN specification in RFC 3168 to specify a scheme that provides more than one feedback signal per RTT in the TCP header. [^tcp-ecn]

[^tcp-ecn]: [More Accurate Explicit Congestion Notification (ECN) Feedback in TCP](https://datatracker.ietf.org/doc/html/draft-ietf-tcpm-accurate-ecn-30)

QUIC is a transport protocol that takes a different approach to connection establishment, congestion control, etc than TCP. QUIC is still a relatively new transport protocol. That said, researchers active in its development have already proposed the inclusion of a mechanism where _peers_ can share granular information about "incipient congestion". Again, I will quote from the experts:

> Some congestion control algorithms would benefit from not only knowing that some packets were marked with Congestion Experienced (CE) bit, but exactly which ones. In the general case, this is not possible with the standard [QUIC] ACK frame, since it only contains cumulative ECN counts. ... [T]he ACCURATE_ACK_ECN frame ... encodes the corresponding ECN codepoint alongside the ACK range. [^quic-ecn]

[^quic-ecn]: [QUIC Accurate ECN Acknowledgements](https://datatracker.ietf.org/doc/draft-seemann-quic-accurate-ack-ecn/)

### What is QUIC?

Again, there's no reason for you to listen to me. Let's hear how QUIC describes itself:

> QUIC provides applications with flow-controlled streams for structured communication, low-latency connection establishment, and network path migration. QUIC includes security measures that ensure confidentiality, integrity, and availability in a range of deployment circumstances. Accompanying documents describe the integration of TLS for key negotiation, loss detection, and an exemplary congestion control algorithm.[^quic-transport]

[^quic-transport]: Iyengar, Jana, and Martin Thomson. 2021. "QUIC: A UDP-Based Multiplexed and Secure Transport" Request for Comments. RFC 9000; RFC Editor. <https://doi.org/10.17487/RFC9000>.

### Why These Things

#### Accurate ECN

Even if applications are (re)designed to leverage the [soon-to-be-widespread adoption](https://corporate.comcast.com/stories/comcast-kicks-off-industrys-first-low-latency-docsis-field-trials) of low-latency connection-oriented protocols, they will not achieve the best possible performance unless the networking software on servers can provide more than one ECN marking per RTT. In other words, an application that could benefit from low-latency connections will require Accurate ECN deployment on the client and server operating systems. Having data on the availability of the deployment of Accurate ECN will build awareness about the importance of support for the protocol.

#### QUIC Transport Parameters

Endpoints that support the QUIC protocol rely on transport parameters (the ones that it declares about itself and the ones that it receives from its peer) in order to determine/set protocol behavior. Documenting how the most popular sites on the internet have configured their QUIC deployments (by looking at the transport parameter values they declare) will provide invaluable information to new QUIC users as more sites begin deployment of the protocol. In addition, monitoring changes to the values of transport parameters over time will allow researchers to decipher changes in the best practices for QUIC deployment.

### The Data

The data available on this website provide a perspective on the deployment of Accurate ECN on the most popular websites on the Internet. Determination of what constitutes the _most popular websites on the Internet_ is made using data from [Tranco](https://tranco-list.eu/).

Beginning with the data on August 30th, 2025, the determination of _most popular websites on the Internet_ is made the same day the data is collected. In other words, the set of sites polled when creating each set of data on/after August 30th, 2025 may differ. Prior to August 30th, 2025, the determination of _most popular websites on the Internet_ was made using the Tranco list from from [September 24th, 2024](https://tranco-list.eu/list/Z3J4G/1000000).

The Tranco ranking is an incredible service and we are thankful to those who maintain it. Because the results published here are not reported in academic publication, there is no way to comply with their request that their work be cited when it is used. To make sure that it is _obvious_ that we owe them a huge debt of gratitude, the requested citation for their work is reproduced below:

> Victor Le Pochat, Tom Van Goethem, Samaneh Tajalizadehkhoob, Maciej Korczyński, and Wouter Joosen. 2019. "Tranco: A Research-Oriented Top Sites Ranking Hardened Against Manipulation," Proceedings of the 26th Annual Network and Distributed System Security Symposium (NDSS 2019). https://doi.org/10.14722/ndss.2019.23386


#### The Files

The data is available at [https://accurecny-data.pages.dev/](https://accurecny-data.pages.dev/). The names of the files indicate the date the data were collected: `YYYYMMDD`. The `.csv` file contains the results of determining whether each of the top 500 most popular websites support Accurate ECN. The `.log` file contains the logging output generated by the tool when collecting the data. See [below](#the-tool) for more information about the tool used to collect the data.

#### The Data Dictionary (Current)

| Field Number | Field Description | Field Type |
| -- | -- | -- |
| 1 | The public IP address of the host taking the measurement. | String |
| 2 | The popularity rank of the site. | Unsigned Integer (in base 10) |
| 3 | The URL of the site. | String |
| 4 | The IP used to determine the status of the site's support for Accurate ECN in TCP. | String |
| 5 | Whether or not the tool successfully made a determination about the site's support for Accurate ECN in TCP. | Boolean |
| 6 | Whether the site supports Accurate ECN in TCP.[^2] | Boolean |
| 7 | The 16 bit value of the TCP flags in the SYN/ACK packet captured when measuring whether the site supports Accurate ECN in TCP. | Unsigned 16-bit Number (in hexadecimal) |
| 8 | The IP used to determine the status of the site's support for Accurate ECN in QUIC. | String |
| 9 | Whether or not the tool successfully made a QUIC connection with the host. |  Boolean |
| 10 | The transport parameters (and their values) received from the peer endpoint. See [Section 18.2 of RFC9000](https://www.rfc-editor.org/rfc/rfc9000.html#name-transport-parameter-definit) for more information about the transport parameters and their values. Unknown transport parameters are included and their values are represented as an array of bytes (in hexadecimal). [`data-tools/tparams.py`](https://github.com/cerfcast/accurecny/) that comes with the tool's code may be helpful in querying the data. | JSON Object |

#### The Data Dictionary (After 2025-01-19)

This data dictionary applies to all data and log files generated _after_ 2025-01-19.

The data now contain information about the status of Accurate ECN deployment for _all_ the hosts serving each of the popular websites. Earlier versions of the data contained information about the status of Accurate ECN deployment for only _one_ of the hosts serving each of the popular websites.

As a result, the data files _may_ contain multiple rows for the same host in the case where a query for the domain name returned multiple `A` (or `AAAA`) resource records in the answers.

Otherwise, there is no change to the meaning of the individual fields in each row of the results. See the list of fields [below](#the-deprecated-data-dictionary-2024-10-01).

**Values That Indicate Accurate ECN Support**

Included below are calculations of the hexadecimal representations of the TCP flags that indicate Accurate ECN support. The goal of this table is to make it easy to quickly assess the results as they are generated. It _should_ be a faithful reproduction of Table 2 in the draft RFC specifying Accurate ECN.

> Note: The `RX` columns are _reserved_ fields.

<pre>
R1  |  R2 |  R3 |  AE | CWR |ECE |URG |ACK |PSH |RST |SYN |FIN |       |            |
3   |  2  |  1  |  0 || 3   |2   |1   |0  ||3   |2   |1   |0   |       |            |
                     ||                   ||                   |       |            |
    |     |     |  0 || 1   |0   |    |1  ||    |    |1   |0   |       |            |
                   0 ||                9  ||               2   |0x0092 | Suppported |
    |     |     |  0 || 1   |1   |    |1  ||    |    |1   |0   |       |            |
                   0 ||                d  ||               2   |0x00d2 | Suppported |
    |     |     |  1 || 0   |0   |    |1  ||    |    |1   |0   |       |            |
                   1 ||                1  ||               2   |0x0112 | Suppported |
    |     |     |  1 || 1   |0   |    |1  ||    |    |1   |0   |       |            |
                   1 ||                9  ||               2   |0x0192 | Suppported |
</pre>


#### The (Deprecated) Data Dictionary (2024-10-01)

This data dictionary applies to all data and log files generated _after_ 2024-10-01.

Each of the data files is formatted as a [CSV](https://en.wikipedia.org/wiki/Comma-separated_values) file. Each row in the file contains data on the status of Accurate ECN support for one of the top 500 most popular sites on the Internet. 

From left to right, the fields are:

| Field Number | Field Description | Field Type |
| -- | -- | -- |
| 1 | The public IP address of the host taking the measurement. | String |
| 2 | The popularity rank of the site. | Unsigned Integer (in base 10) |
| 3 | The URL of the site. | String |
| 4 | The IP used to determine the status of the site's support for Accurate ECN in TCP. | String |
| 5 | Whether or not the tool successfully made a determination about the site's support for Accurate ECN in TCP. | Boolean |
| 6 | Whether the site supports Accurate ECN in TCP.[^2] | Boolean |
| 7 | The 16 bit value of the TCP flags in the SYN/ACK packet captured when measuring whether the site supports Accurate ECN in TCP. | Unsigned 16-bit Number (in hexadecimal) |
| 8 | The IP used to determine the status of the site's support for Accurate ECN in QUIC. | String |
| 9 | Whether or not the tool successfully made a determination about the site's support for Accurate ECN in QUIC. | Boolean |
| 10 | Whether the site supports Accurate ECN in QUIC.[^2] | Boolean |

#### The (Really Deprecated) Data Dictionary (2024-09-27)

This data dictionary applies to the _single_ pair of data and log file generated during a measurement on 2024-09-27.

Each of the data files is formatted as a [CSV](https://en.wikipedia.org/wiki/Comma-separated_values) file. Each row in the file contains data on the status of Accurate ECN support for one of the top 500 most popular sites on the Internet. 

From left to right, the fields are:

| Field Number | Field Description | Field Type |
| -- | -- | -- |
| 1 | The popularity rank of the site. | Unsigned Integer (in base 10) |
| 2 | The URL of the site. | String |
| 3 | The IP used to determine the status of the site's support for Accurate ECN. | String |
| 4 | Whether or not the tool successfully made a determination about the site's support for Accurate ECN. | Boolean |
| 5 | Whether the site supports Accurate ECN.[^2] | Boolean |
| 6 | The 16 bit value of the TCP flags in the SYN/ACK packet. | Unsigned 16-bit Number (in hexadecimal) |

[^2]: The value of this field will be false if the tool could not successfully make a determination about the site's support.

### The Tool

The tool used to collect this data is open source (licensed GPLv3) and available at [http://www.github.com/cerfcast/accurecny](http://www.github.com/cerfcast/accurecny). We would _love_ to have you contribute patches and/or data you collected. Please [contact us](#contact-us) or [submit an issue](https://github.com/cerfcast/accurecny/issues).

Information about how to compile and use the tool is available at the [Github repository](https://github.com/cerfcast/accurecny/).

### Contact Us

If you have any questions about Accurecny, please contact Will Hawkins by [email](mailto:hawkinsw@obs.cr) or on [X](http://x.com/hawkinsw).

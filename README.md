# CertSeeker

**CertSeeker** is a lightweight OSINT tool designed to search for domains and subdomains associated with an organization using the [crt.sh](https://crt.sh/) Certificate Transparency log database. It extracts unique subdomains from issued SSL/TLS certificates and presents the results in a clean, exportable format.

---

## Features

- Queries the `crt.sh` API for issued certificates.
- Extracts and deduplicates subdomains using regex parsing.
- Supports output to file (optional).
- Designed for red teamers, bug bounty hunters, and OSINT enthusiasts.
- Minimal dependencies, easy to run on any system with Python 3.

---

## Installation

```bash
git clone https://github.com/masterpiper211/CertSeeker.git
cd CertSeeker
pip install -r requirements.txt

> Note: If requirements.txt is not provided, manually install requests.



pip install requests


---

Usage

python cert_seeker.py -d example.com

Optional Arguments

Flag	Description

-d, --domain	Target domain to search (required)
-o, --output	Output results to a file (optional)



---

Example

python cert_seeker.py -d uber.com -o uber_subdomains.txt

This will save all discovered subdomains for uber.com to a file named uber_subdomains.txt.


---

Screenshot




---

License

This project is licensed under the MIT License.


---

Credits

Inspired by the power of crt.sh

Developed by masterpiper211



---

Disclaimer

This tool is intended for educational and lawful security research purposes only. Use responsibly.

# ShadowScan - Advanced Shodan Intelligence Platform

A professional dark-themed GUI wrapper for Shodan reconnaissance operations designed for security professionals and penetration testers.

![Screenshot of ShadowScan UI](https://github.com/aingram702/ShadowScan/blob/main/shadowscan/sc0.png)

## 🚀 Features

- 🔍 **Advanced Search** - Full Shodan search with filters, quick presets, and facet analysis
- 🖥️ **Host Lookup** - Detailed host information including services, banners, and vulnerabilities
- 🌐 **DNS Tools** - Forward and reverse DNS lookups
- 💥 **Exploit Search** - Find exploits by product, version, or CVE
- 🍯 **Honeypot Detection** - Analyze targets for honeypot indicators
- 📡 **Protocol Scanning** - Search by specific protocols and services
- 💾 **Save/Export** - Export results to JSON, CSV, or generate reports
- 🎨 **Dark Hacker Theme** - Professional terminal-style dark UI

## 📋 Requirements

- Python 3.7+
- Shodan API Key (get one at https://shodan.io)

## 🔧 Installation

### Option 1: Quick Start

```bash
# Clone the repository
git clone https://github.com/yourusername/shadowscan.git
cd shadowscan

# Install dependencies
pip install -r requirements.txt

# Run the application
python run.py

Option 2: Install as Package
pip install -e .
shadowscan
Option 3: Single File Version
Download shadowscan_standalone.py and run:
pip install shodan requests
python shadowscan_standalone.py
📖 Usage

Launch ShadowScan
Enter your Shodan API key
Click "Connect" to authenticate
Use the various tabs for different operations:
Search: Query Shodan's database
Host: Lookup specific IP addresses
DNS: Resolve domains and IPs
Exploits: Search for known exploits
Honeypot: Analyze honeypot probability
Protocols: Quick protocol-based searches
Saved: View and manage saved results



🔑 Getting a Shodan API Key

Create an account at Shodan.io
Navigate to "My Account"
Copy your API key
Paste it into ShadowScan

📸 Screenshots
Main Search Interface
<img src="docs/search.png" alt="Search Tab" />
Host Information
<img src="docs/host.png" alt="Host Tab" />
Exploit Search
<img src="docs/exploits.png" alt="Exploits Tab" />
⚠️ Legal Disclaimer
This tool is intended for authorized security testing and research purposes only. Users are responsible for ensuring they have proper authorization before scanning any systems. Unauthorized access to computer systems is illegal.
📄 License
MIT License - See LICENSE file for details.
🤝 Contributing
Contributions are welcome! Please feel free to submit pull requests.
📧 Contact
For issues and feature requests, please use the GitHub issue tracker.

---

### `LICENSE`

```text
MIT License

Copyright (c) 2024 ShadowScan

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE

SOFTWARE.


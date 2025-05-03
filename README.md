<h1 align="center">🛡️ FavFreak v2.0</h1>



"""\u001b[32m


 /$$$$$$$$                  /$$$$$$$$                          /$$        /$$$$$$      /$$$$$$ 
| $$_____/                 | $$_____/                         | $$       /$$__  $$    /$$$_  $$
| $$    /$$$$$$  /$$    /$$| $$    /$$$$$$  /$$$$$$   /$$$$$$ | $$   /$$|__/  \ $$   | $$$$\ $$
| $$$$$|____  $$|  $$  /$$/| $$$$$/$$__  $$/$$__  $$ |____  $$| $$  /$$/  /$$$$$$/   | $$ $$ $$
| $$__/ /$$$$$$$ \  $$/$$/ | $$__/ $$  \__/ $$$$$$$$  /$$$$$$$| $$$$$$/  /$$____/    | $$\ $$$$
| $$   /$$__  $$  \  $$$/  | $$  | $$     | $$_____/ /$$__  $$| $$_  $$ | $$         | $$ \ $$$
| $$  |  $$$$$$$   \  $/   | $$  | $$     |  $$$$$$$|  $$$$$$$| $$ \  $$| $$$$$$$$/$$|  $$$$$$/
|__/   \_______/    \_/    |__/  |__/      \_______/ \_______/|__/  \__/|________/__/ \______/ 



         \u001b[35m- FavFreak v2.0 | Coded with \u001b[31m<3\u001b[0m\u001b[35m by LiquidSec\u001b[0m
"""


<p align="center">
  <i>Favicon Hash-Based Asset Mapper - Modernized and Reborn</i><br>
  <strong>Security Reconnaissance • Technology Fingerprinting • Shodan Integration</strong>
</p>

<p align="center">
  ⚙️ <code>Python 3</code> • 🚀 <code>Multi-threaded</code> • 🔍 <code>Fingerprint Matching</code> • 🧠 <code>Smart Recon</code>
</p>

---

## 🔥 What is FavFreak v2.0?

**FavFreak v2.0** is a modern, fast, and flexible tool that identifies favicon hashes for given URLS file. It's ideal for bug bounty hunters, penetration testers, and red teamers looking to rapidly identify exposed services or tech stacks.

> 🧪 Inspired by FavFreak of Devansh Batham, with Uncover mode output and Shodan dorks generator ❤️.

---

## 🚀 Features

- ⚡ **Multi-threaded favicon fetching**
- 🔐 **Favicon hashing using mmh3**
- 📚 **Built-in fingerprint matching**
- 🧭 **Optional Shodan dork generation**
- 💾 **Output hashes to files**
- 🔧 **`--no-favicon` option for manual URLs if your input URLs already point to a favicon**
- ✅ **Python >=3.9 compatible and cleaner codebase**

---

## 📦 Installation

Clone the repo and install the dependencies:

```bash

git clone https://github.com/yourusername/favfreak2.git

cd favfreak2

pip install -r requirements.txt

```bash

⚙️ Usage

Basic:

cat urls.txt | python3 favfreak2.py

With options:

cat urls.txt | python3 favfreak2.py --output output --shodan --uncover

Available Arguments:

##Flag##       ##Description##

--output	   Directory to save hash result files per hash
--uncover      Uncover output mode for uncover tool from project discovery
--shodan	   Print Shodan search dorks for identified hashes
--no-favicon   Don't append /favicon.ico (use raw URLs as-is)


📄 License

MIT License – feel free to fork, improve, and contribute responsibly.



🙏 Credits

    🧠 Original author: Devansh Batham

    🛠️ Modernized & enhanced: LiquidSec

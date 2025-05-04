<h1 align="center">🛡️ FavFreak v2.0</h1>

<pre><code>
 /$$$$$$$$                  /$$$$$$$$                          /$$        /$$$$$$      /$$$$$$ 
| $$_____/                 | $$_____/                         | $$       /$$__  $$    /$$$_  $$
| $$    /$$$$$$  /$$    /$$| $$    /$$$$$$  /$$$$$$   /$$$$$$ | $$   /$$|__/  \ $$   | $$$$\ $$
| $$$$$|____  $$|  $$  /$$/| $$$$$/$$__  $$/$$__  $$ |____  $$| $$  /$$/  /$$$$$$/   | $$ $$ $$
| $$__/ /$$$$$$$ \  $$/$$/ | $$__/ $$  \__/ $$$$$$$$  /$$$$$$$| $$$$$$/  /$$____/    | $$\ $$$$
| $$   /$$__  $$  \  $$$/  | $$  | $$     | $$_____/ /$$__  $$| $$_  $$ | $$         | $$ \ $$$
| $$  |  $$$$$$$   \  $/   | $$  | $$     |  $$$$$$$|  $$$$$$$| $$ \  $$| $$$$$$$$/$$|  $$$$$$/
|__/   \_______/    \_/    |__/  |__/      \_______/ \_______/|__/  \__/|________/__/ \______/ 
</code></pre>

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

> 🧪 Inspired by FavFreak of Devansh Batham, with Uncover mode output and Shodan query output using API_KEY ❤️.

---

## 🚀 Features

- ⚡ **Multi-threaded favicon fetching**
- 🔐 **Favicon hashing using mmh3**
- 📚 **Built-in fingerprint matching**
- 🧭 **Optional Uncover mode output and Shodan database query**
- 💾 **Output hashes to files**
- 🔧 **`--no-favicon` option for manual URLs if your input URLs already point to a favicon**
- ✅ **Python >=3.9 compatible and cleaner codebase**

---

## 📦 Installation

Clone the repo and install the dependencies:

```bash

git clone https://github.com/Liquid1998/favfreak2.git

cd favfreak2

pip install -r requirements.txt
```

## USAGE

Basic Usage:

```bash

cat urls.txt | python3 favfreak2.py --output output_dir
```
If you want a Uncover mode output and want to query shodan database

```bash

cat urls.txt | python3 favfreak2.py --output output_dir --uncover --shodan --api-key API_KEY
```

## Results

Basic usage results with uncover output mode:

```
cat url.txt | python3 favfreak2.py --uncover

/$$$$$$$$                  /$$$$$$$$                          /$$        /$$$$$$      /$$$$$$ 
| $$_____/                 | $$_____/                         | $$       /$$__  $$    /$$$_  $$
| $$    /$$$$$$  /$$    /$$| $$    /$$$$$$  /$$$$$$   /$$$$$$ | $$   /$$|__/  \ $$   | $$$$\ $$
| $$$$$|____  $$|  $$  /$$/| $$$$$/$$__  $$/$$__  $$ |____  $$| $$  /$$/  /$$$$$$/   | $$ $$ $$
| $$__/ /$$$$$$$ \  $$/$$/ | $$__/ $$  \__/ $$$$$$$$  /$$$$$$$| $$$$$$/  /$$____/    | $$\ $$$$
| $$   /$$__  $$  \  $$$/  | $$  | $$     | $$_____/ /$$__  $$| $$_  $$ | $$         | $$ \ $$$
| $$  |  $$$$$$$   \  $/   | $$  | $$     |  $$$$$$$|  $$$$$$$| $$ \  $$| $$$$$$$$/$$|  $$$$$$/
|__/   \_______/    \_/    |__/  |__/      \_______/ \_______/|__/  \__/|________/__/ \______/ 



         - FavFreak v2.0 | Coded with <3 by LiquidSec

[*] Fetching favicons...
[INFO] Fetched https://google.com

[*] Completed in 0.36 seconds.

----------------------------------------------------------------------
[Favicon mmh3 Hash Results] - 

[Hash] 708578229
     https://google.com

----------------------------------------------------------------------
[Google] 708578229 - count: 1
     https://google.com

----------------------------------------------------------------------
[Favicon md5 Hash Results] - 

[Hash] f3418a443e7d841097c714d69ec4bcb8
     https://google.com

----------------------------------------------------------------------
[Google] f3418a443e7d841097c714d69ec4bcb8 - count: 1
     https://google.com

----------------------------------------------------------------------
[Uncover mode output] - 

[uncover] uncover -q 'http.favicon.hash:708578229' -e shodan,fofa,censys -silent

----------------------------------------------------------------------
[Summary]

 Count      Hash
~ [1]  : [708578229]
~ [1]  : [f3418a443e7d841097c714d69ec4bcb8]
```

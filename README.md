# Profil3r

<a href="https://www.buymeacoffee.com/givocefo" target="_blank"><img src="https://cdn.buymeacoffee.com/buttons/default-orange.png" alt="Buy Me A Coffee" height="41" width="174"></a>

Profil3r is an [OSINT](https://en.wikipedia.org/wiki/Open-source_intelligence) tool that allows you to find potential profiles of a person on social networks, as well as their email addresses. This program also alerts you to the presence of a data leak for the found emails.

![](https://i.imgur.com/MObvrJg.gif)
## 💡 Prerequisite
[Python 3](https://www.python.org/)

## 🛠️ Installation
```bash
git clone https://github.com/coreylad/Profil3r.git
cd Profil3r/
python3 -m pip install .
```
## Features

#### Emails 
- [x] Data leaks
- [x] Emails

#### Social
- [x] Instagram
- [x] Facebook
- [x] Twitter
- [x] Tiktok

#### Porn
- [x] Onlyfans

## Report 📖

A report in JSON format is automatically generated in the `reports` folder

## 📚 Example

```bash
python3 profil3r john doe
```

Run these commands from the repository root (where `config.json` is located).
You can also use `python3 -m profil3r john doe` or the legacy
`python3 profil3r.py john doe` entry point.

## 📝 License

This project is under the MIT license.
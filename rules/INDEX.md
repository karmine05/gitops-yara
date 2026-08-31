# Rule index

Generated from `https://github.com/elastic/protections-artifacts.git` @ `9c334cf8298d` on 2026-08-31.

Pass any `sigurl` below to `yara_file` or `yara_process`. One allowlist
entry in agent options covers this whole tree.

## macos

| File | Rules | Size | sigurl |
|---|---:|---:|---|
| `macos/_all.yar` | 150 | 150 KB | `https://raw.githubusercontent.com/karmine05/gitops-yara/main/rules/macos/_all.yar` |
| `macos/backdoor.yar` | 7 | 6 KB | `https://raw.githubusercontent.com/karmine05/gitops-yara/main/rules/macos/backdoor.yar` |
| `macos/creddump.yar` | 1 | 1 KB | `https://raw.githubusercontent.com/karmine05/gitops-yara/main/rules/macos/creddump.yar` |
| `macos/cryptominer.yar` | 4 | 3 KB | `https://raw.githubusercontent.com/karmine05/gitops-yara/main/rules/macos/cryptominer.yar` |
| `macos/exploit.yar` | 1 | 1 KB | `https://raw.githubusercontent.com/karmine05/gitops-yara/main/rules/macos/exploit.yar` |
| `macos/hacktool.yar` | 3 | 4 KB | `https://raw.githubusercontent.com/karmine05/gitops-yara/main/rules/macos/hacktool.yar` |
| `macos/infostealer.yar` | 12 | 17 KB | `https://raw.githubusercontent.com/karmine05/gitops-yara/main/rules/macos/infostealer.yar` |
| `macos/trojan.yar` | 60 | 50 KB | `https://raw.githubusercontent.com/karmine05/gitops-yara/main/rules/macos/trojan.yar` |
| `macos/virus.yar` | 7 | 5 KB | `https://raw.githubusercontent.com/karmine05/gitops-yara/main/rules/macos/virus.yar` |

## linux

| File | Rules | Size | sigurl |
|---|---:|---:|---|
| `linux/_all.yar` | 957 | 756 KB | `https://raw.githubusercontent.com/karmine05/gitops-yara/main/rules/linux/_all.yar` |
| `linux/backdoor.yar` | 6 | 5 KB | `https://raw.githubusercontent.com/karmine05/gitops-yara/main/rules/linux/backdoor.yar` |
| `linux/cryptominer.yar` | 128 | 91 KB | `https://raw.githubusercontent.com/karmine05/gitops-yara/main/rules/linux/cryptominer.yar` |
| `linux/downloader.yar` | 1 | 1 KB | `https://raw.githubusercontent.com/karmine05/gitops-yara/main/rules/linux/downloader.yar` |
| `linux/exploit.yar` | 122 | 94 KB | `https://raw.githubusercontent.com/karmine05/gitops-yara/main/rules/linux/exploit.yar` |
| `linux/generic.yar` | 70 | 58 KB | `https://raw.githubusercontent.com/karmine05/gitops-yara/main/rules/linux/generic.yar` |
| `linux/hacktool.yar` | 58 | 45 KB | `https://raw.githubusercontent.com/karmine05/gitops-yara/main/rules/linux/hacktool.yar` |
| `linux/packer.yar` | 1 | 1 KB | `https://raw.githubusercontent.com/karmine05/gitops-yara/main/rules/linux/packer.yar` |
| `linux/proxy.yar` | 1 | 1 KB | `https://raw.githubusercontent.com/karmine05/gitops-yara/main/rules/linux/proxy.yar` |
| `linux/ransomware.yar` | 28 | 24 KB | `https://raw.githubusercontent.com/karmine05/gitops-yara/main/rules/linux/ransomware.yar` |
| `linux/rootkit.yar` | 27 | 34 KB | `https://raw.githubusercontent.com/karmine05/gitops-yara/main/rules/linux/rootkit.yar` |
| `linux/shellcode.yar` | 8 | 6 KB | `https://raw.githubusercontent.com/karmine05/gitops-yara/main/rules/linux/shellcode.yar` |
| `linux/trojan.yar` | 441 | 326 KB | `https://raw.githubusercontent.com/karmine05/gitops-yara/main/rules/linux/trojan.yar` |
| `linux/virus.yar` | 5 | 4 KB | `https://raw.githubusercontent.com/karmine05/gitops-yara/main/rules/linux/virus.yar` |
| `linux/webshell.yar` | 2 | 1 KB | `https://raw.githubusercontent.com/karmine05/gitops-yara/main/rules/linux/webshell.yar` |
| `linux/worm.yar` | 4 | 3 KB | `https://raw.githubusercontent.com/karmine05/gitops-yara/main/rules/linux/worm.yar` |

## windows

| File | Rules | Size | sigurl |
|---|---:|---:|---|
| `windows/_all.yar` | 2024 | 2484 KB | `https://raw.githubusercontent.com/karmine05/gitops-yara/main/rules/windows/_all.yar` |
| `windows/attacksimulation.yar` | 1 | 1 KB | `https://raw.githubusercontent.com/karmine05/gitops-yara/main/rules/windows/attacksimulation.yar` |
| `windows/backdoor.yar` | 4 | 5 KB | `https://raw.githubusercontent.com/karmine05/gitops-yara/main/rules/windows/backdoor.yar` |
| `windows/clickfraud.yar` | 1 | 1 KB | `https://raw.githubusercontent.com/karmine05/gitops-yara/main/rules/windows/clickfraud.yar` |
| `windows/cryptominer.yar` | 2 | 2 KB | `https://raw.githubusercontent.com/karmine05/gitops-yara/main/rules/windows/cryptominer.yar` |
| `windows/exploit.yar` | 11 | 10 KB | `https://raw.githubusercontent.com/karmine05/gitops-yara/main/rules/windows/exploit.yar` |
| `windows/generic.yar` | 318 | 246 KB | `https://raw.githubusercontent.com/karmine05/gitops-yara/main/rules/windows/generic.yar` |
| `windows/hacktool.yar` | 68 | 80 KB | `https://raw.githubusercontent.com/karmine05/gitops-yara/main/rules/windows/hacktool.yar` |
| `windows/infostealer.yar` | 5 | 5 KB | `https://raw.githubusercontent.com/karmine05/gitops-yara/main/rules/windows/infostealer.yar` |
| `windows/packer.yar` | 1 | 1 KB | `https://raw.githubusercontent.com/karmine05/gitops-yara/main/rules/windows/packer.yar` |
| `windows/pup.yar` | 3 | 3 KB | `https://raw.githubusercontent.com/karmine05/gitops-yara/main/rules/windows/pup.yar` |
| `windows/ransomware.yar` | 99 | 106 KB | `https://raw.githubusercontent.com/karmine05/gitops-yara/main/rules/windows/ransomware.yar` |
| `windows/remoteadmin.yar` | 1 | 1 KB | `https://raw.githubusercontent.com/karmine05/gitops-yara/main/rules/windows/remoteadmin.yar` |
| `windows/rootkit.yar` | 100 | 136 KB | `https://raw.githubusercontent.com/karmine05/gitops-yara/main/rules/windows/rootkit.yar` |
| `windows/shellcode.yar` | 6 | 5 KB | `https://raw.githubusercontent.com/karmine05/gitops-yara/main/rules/windows/shellcode.yar` |
| `windows/trojan.yar` | 509 | 526 KB | `https://raw.githubusercontent.com/karmine05/gitops-yara/main/rules/windows/trojan.yar` |
| `windows/virus.yar` | 3 | 3 KB | `https://raw.githubusercontent.com/karmine05/gitops-yara/main/rules/windows/virus.yar` |
| `windows/vulndriver.yar` | 833 | 1288 KB | `https://raw.githubusercontent.com/karmine05/gitops-yara/main/rules/windows/vulndriver.yar` |
| `windows/wiper.yar` | 4 | 4 KB | `https://raw.githubusercontent.com/karmine05/gitops-yara/main/rules/windows/wiper.yar` |

## multi

| File | Rules | Size | sigurl |
|---|---:|---:|---|
| `multi/_all.yar` | 55 | 63 KB | `https://raw.githubusercontent.com/karmine05/gitops-yara/main/rules/multi/_all.yar` |
| `multi/attacksimulation.yar` | 1 | 1 KB | `https://raw.githubusercontent.com/karmine05/gitops-yara/main/rules/multi/attacksimulation.yar` |
| `multi/cryptominer.yar` | 1 | 1 KB | `https://raw.githubusercontent.com/karmine05/gitops-yara/main/rules/multi/cryptominer.yar` |
| `multi/eicar.yar` | 1 | 1 KB | `https://raw.githubusercontent.com/karmine05/gitops-yara/main/rules/multi/eicar.yar` |
| `multi/generic.yar` | 1 | 1 KB | `https://raw.githubusercontent.com/karmine05/gitops-yara/main/rules/multi/generic.yar` |
| `multi/hacktool.yar` | 24 | 30 KB | `https://raw.githubusercontent.com/karmine05/gitops-yara/main/rules/multi/hacktool.yar` |
| `multi/ransomware.yar` | 12 | 12 KB | `https://raw.githubusercontent.com/karmine05/gitops-yara/main/rules/multi/ransomware.yar` |
| `multi/trojan.yar` | 15 | 18 KB | `https://raw.githubusercontent.com/karmine05/gitops-yara/main/rules/multi/trojan.yar` |

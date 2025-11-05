# Aegis — FIM + Port Scanner em C

> **Dois utilitários de cibersegurança em C, simples e práticos:**
>
> * **aegisFIM**: monitor de integridade de arquivos (File Integrity Monitoring)
> * **aegisport**: scanner de portas TCP não-bloqueante
>
> **Um comando só**? Use o script `./aegis` (em português) para rodar tudo sem complicação.

---

##  Visão Geral

* **aegisFIM** fotografa um diretório (baseline: caminho, tamanho, mtime, SHA‑256) e depois compara o estado atual, mostrando **ADD/DEL/MOD**. Tem modo **CLI**, **watch** e **TUI** (ncurses).
* **aegisport** faz varredura de portas TCP usando `connect()` **não bloqueante** + `poll()` (concorrência alta), com `-v` (verbose) e `--json` para exportar resultados.
* **Script `aegis`**: interface unificada em **português** para “verificar” pastas, “vigiar” em loop e escanear “portas”.

## Recursos

### aegisFIM

* **Comandos em português**: `verificar`, `vigiar`, `interface` (TUI)
* **Cria baseline automaticamente** (se não existir)
* **Ignora ruído padrão**: `aegisfim.baseline.tsv`, diretórios `.git`, `node_modules`, `dist`, `build`, `vendor`, `.aegisfim`
* **Limite de tamanho por arquivo**: 50 MB (configurável no código)
* **TUI (ncurses)** com atalhos: `i` (init), `c` (check), `w` (watch on/off), `+/-` (intervalo), `q` (sair)

### aegisport

* **Não-bloqueante** com `poll()` e **concorrência configurável** (`-c`)
* **Timeout por rodada** (`-t` ms)
* **Faixas/listas de portas**: `-p 1-1024,3306,5432`
* **Verbose** (`-v`) e **saída JSON** (`--json arquivo`)

---

##  Requisitos

* **Linux/WSL (Ubuntu)**
* **CMake** e toolchain: `build-essential`
* **OpenSSL** (crypto): `libssl-dev`
* **ncurses** (TUI): `libncurses-dev`
* (opcional) **netcat-openbsd** para testes de portas

Instalação rápida:

```bash
sudo apt-get update
sudo apt-get install -y build-essential cmake libssl-dev libncurses-dev netcat-openbsd
```

---

##  Build

```bash
rm -rf build
cmake -S . -B build
cmake --build build -j
```

Isso gera:

* `./build/aegisfim`
* `./build/aegisport`

---

##  Um comando só (script em português)

Crie o arquivo `./aegis` na raiz (se já existir, pule):

```bash
cat > ./aegis <<'BASH'
#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN_FIM="$ROOT/build/aegisfim"
BIN_PORT="$ROOT/build/aegisport"
# compila se precisar
if [[ ! -x "$BIN_FIM" || ! -x "$BIN_PORT" ]]; then
  echo " Compilando (primeira execução)..."
  cmake -S "$ROOT" -B "$ROOT/build" >/dev/null
  cmake --build "$ROOT/build" -j >/dev/null
fi
CMD="${1:-verificar}"; shift || true
case "$CMD" in
  verificar)  DIR="${1:-.}";         exec "$BIN_FIM" verificar -r "$DIR" ;;
  vigiar)     DIR="${1:-.}"; INT="${2:-3}"; exec "$BIN_FIM" vigiar -r "$DIR" -i "$INT" ;;
  interface)  DIR="${1:-.}"; INT="${2:-3}"; exec "$BIN_FIM" interface -r "$DIR" -i "$INT" ;;
  portas)     HOST="${1:-127.0.0.1}"; PORTS="${2:-1-1024}"; shift 2 || true; exec "$BIN_PORT" -h "$HOST" -p "$PORTS" "$@" ;;
  *) echo "Uso: ./aegis [verificar [DIR] | vigiar [DIR] [SEG] | interface [DIR] [SEG] | portas HOST [PORTAS]]"; exit 1 ;;
esac
BASH
chmod +x ./aegis
```

### Uso instantâneo

```bash
./aegis 
./aegis verificar . 
./aegis vigiar . 3 
./aegis interface . 3 
./aegis portas 127.0.0.1 8080,9000,9001
```

> **Dica**: coloque o script no PATH para rodar de qualquer lugar:
>
> ```bash
> mkdir -p ~/.local/bin && cp ./aegis ~/.local/bin/
> echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.zshrc && source ~/.zshrc
> ```

---

##  Uso do aegisFIM (CLI/TUI)

### Verificar (cria baseline se necessário):

```bash
./build/aegisfim verificar -r .
```

Saída típica:

```
 baseline criada com 7 arquivos -> ./aegisfim.baseline.tsv
[ADD] foo.txt
[MOD] src/main.c
...
Resumo: +1 -0 ~1 =5 (total atual: 7)
```

### Vigiar (loop):

```bash
./build/aegisfim vigiar -r . -i 3
```

### Interface (TUI):

```bash
./build/aegisfim interface -r . -i 3
```

Atalhos: `i` (init), `c` (check), `w` (watch), `+/-` (intervalo), `q` (sair)

> **Boas práticas**: mantenha a baseline **dentro da pasta** (nome padrão `aegisfim.baseline.tsv`) — o projeto já ignora esse arquivo. Para evitar ruído, arquivos >50MB são ignorados por padrão.

---

##  Uso do aegisport (scanner)

### Básico

```bash
./build/aegisport -h 127.0.0.1 -p 1-1024
```

### Faixas/listas, concorrência e timeout

```bash
./build/aegisport -h 127.0.0.1 -p 1-1024,3306,5432 -c 500 -t 300 -v --json scan.json
```

Saída:

```
Alvo: 127.0.0.1 (127.0.0.1)
Params: ports="1-1024,3306,5432" conc=500 timeout=300ms
OPEN   8080
OPEN   9000
...
Total abertas: 3 de 1026 portas testadas. (12.34 ms)
JSON salvo em scan.json
```

### Testes rápidos (abrindo portas locais)

```bash
python3 -m http.server 8080
# ou
nc -l -p 9999
```

Depois:

```bash
./build/aegisport -h 127.0.0.1 -p 8080,9999
```

> **Atenção**: Porta 53 (DNS) costuma escutar em `127.0.0.53` (systemd-resolved) e/ou IPs específicos. Escaneie o **IP onde o serviço está listening**.

---

##  Estrutura do repositório

```
.
├── aegis                 # script (um comando só, PT-BR)
├── CMakeLists.txt
├── include/
│   └── aegisfim.h
├── src/
│   ├── baseline.c
│   ├── hash.c
│   ├── main.c            # comandos em português (verificar/vigiar/interface)
│   ├── scan.c
│   ├── tui.c             # interface ncurses
│   └── aegisport.c       # scanner de portas TCP
└── build/                # artefatos de compilação
```

---

##  Configuração & Notas

* **Ignorados por padrão (FIM):** `aegisfim.baseline.tsv`, `.git/`, `node_modules/`, `dist/`, `build/`, `vendor/`, `.aegisfim/`
* **Hash:** SHA‑256 via OpenSSL (`OpenSSL::Crypto`)
* **Tamanho máx arquivo:** 50 MB (`AEGIS_MAX_FILE_SIZE` em `include/aegisfim.h`)
* **Saída JSON (aegisport):** `--json arquivo` + `-v` para log detalhado

---

##  Roadmap (idéias de evolução)

* `--ignore "*.log,tmp/**"` (glob) no FIM
* Assinatura da baseline (HMAC) para integridade
* Watch **em tempo real** (inotify) além do polling
* Export do FIM em **JSON**/**SARIF** (CI)
* **Alertas**: Slack/Discord/email ao detectar mudanças
* aegisport: **banner grab** opcional (HTTP/SMTP), limite por taxa, perfis predefinidos

---

##  Ética & Responsabilidade

* Use o scanner **apenas em hosts que você possui/tem permissão explícita**.
* O FIM não “julga intenção”; ele mostra **o que mudou**. Cabe a você tratar alertas e investigar.

---

##  Créditos

Feito com C, café e teimosia. 😄

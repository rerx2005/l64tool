# l64tool

Codificador e decodificador de arquivos `.l64` do Farming Simulator — compila, cifra, decifra e decompila scripts Luau/LuaJIT.

Suporta os formatos:
- **Luau** (FS23 / FS25 / FS26) — codificação, compilação, decodificação e decompilação (v6) / listing (v3)
- **LuaJIT** (FS19 / FS20 / FS22) — codificação, compilação, decodificação e disassembly de bytecode

### Versões suportadas

| Target | Engine | Bytecode |
|--------|--------|----------|
| `fs19` | LuaJIT | v2 |
| `fs20` | LuaJIT | v2 |
| `fs22` | LuaJIT | v2 |
| `fs23` | Luau   | v3 |
| `fs25` | Luau   | v3 |
| `fs26` | Luau   | v6 |

## Build

```sh
git clone --recursive https://github.com/rerx2005/l64tool.git
cd l64tool
cargo build --release
```

## Uso

```
l64tool [OPTIONS] [COMMAND]
```

### Comandos

| Comando | Descrição |
|---------|-----------|
| `encoder` | Codifica arquivos Lua/bytecode em `.l64` cifrados |
| `decoder` | Decodifica arquivos `.l64` em bytecode ou código-fonte |

### Opções Globais

| Flag | Descrição |
|------|-----------|
| `-l, --licenses` | Mostra licenças de terceiros |
| `-h, --help` | Mostra ajuda |
| `-V, --version` | Mostra versão |

### Encoder

```
l64tool encoder [OPTIONS] --target <TARGET>
```

| Flag | Descrição |
|------|-----------|
| `-f, --file <FILE>` | Codifica um único arquivo |
| `-d, --dir <DIR>` | Codifica todos os arquivos de um diretório |
| `-b, --batch <FILES...>` | Codifica múltiplos arquivos |
| `-r, --recursive` | Percorre subdiretórios (com `--dir`) |
| `-o, --output <PATH>` | Caminho de saída (somente para arquivo único) |
| `-c, --compile-code` | Compila código-fonte para bytecode antes de codificar |
| `-p, --preserve-symbols` | Preserva nomes de variáveis e funções no bytecode |
| `-v, --verbose` | Saída detalhada |
| `-t, --target <TARGET>` | Versão alvo: `fs19`, `fs20`, `fs22`, `fs23`, `fs25`, `fs26` |
| `-O, --overwrite` | Sobrescreve arquivos existentes |

### Decoder

```
l64tool decoder [OPTIONS]
```

| Flag | Descrição |
|------|-----------|
| `-f, --file <FILE>` | Decodifica um único arquivo `.l64` |
| `-d, --dir <DIR>` | Decodifica todos os `.l64` de um diretório |
| `-b, --batch <FILES...>` | Decodifica múltiplos arquivos `.l64` |
| `-r, --recursive` | Percorre subdiretórios (com `--dir`) |
| `-o, --output <PATH>` | Caminho de saída |
| `-s, --source-code` | Decompila/disassembla o bytecode para código legível |
| `-t, --target-source-code <TARGET>` | Força a linguagem para decompilação: `luajit`, `luau` (auto-detectado por padrão) |
| `-v, --verbose` | Saída detalhada |
| `-O, --overwrite` | Sobrescreve arquivos existentes |

### Exemplos

```sh
# Compilar e codificar um script Lua para FS25
l64tool encoder -f myscript.lua -c -t fs25

# Codificar bytecode para FS22 (sem compilação)
l64tool encoder -f myscript.luac -t fs22

# Codificar diretório recursivamente para FS25
l64tool encoder -d scripts/ -r -c -t fs25 -O

# Decodificar arquivo .l64 para bytecode
l64tool decoder -f scripts/events.l64

# Decodificar e decompilar para código-fonte Luau (auto-detecta a linguagem)
l64tool decoder -f scripts/events.l64 -s

# Forçar decompilação como Luau
l64tool decoder -f scripts/events.l64 -s -t luau

# Decodificar diretório inteiro com decompilação
l64tool decoder -d scripts/ -r -s -O

# Batch de arquivos
l64tool decoder -b scripts/events.l64 scripts/game.l64 -s
```

Os arquivos de saída são gerados no mesmo diretório do arquivo original.

## Referências

- [luau-lang/luau](https://github.com/luau-lang/luau) — compilador Luau (vendor)
- [LuaJIT/LuaJIT](https://luajit.org/) — compilador LuaJIT (via mlua)
- [Paint-a-Farm/lantern](https://github.com/Paint-a-Farm/lantern) — decompilador Luau
- [scfmod/fs-utils](https://github.com/scfmod/fs-utils) — ferramenta de referência em Rust
- [chill1Penguin/l64decode](https://github.com/chill1Penguin/l64decode) — decoder em Python para FS19

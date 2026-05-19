# l6426

Decifrador e decompilador de arquivos `.l64` do Farming Simulator para bytecode ou código-fonte Lua (`.lua`).

Suporta os formatos:
- **Luau** (FS25) — padrão e DLC (decodificação + decompilação)
- **LuaJIT** (FS17 / FS19 / FS22) — versões 3 e 4 (somente decodificação)

## Build

```sh
cargo build --release
```

## Uso

```
l6426 [OPTIONS]
```

### Flags

| Flag | Descrição |
|------|-----------|
| `-f, --file <FILE>` | Decodifica um único arquivo `.l64` |
| `-d, --dir <DIR>` | Decodifica todos os `.l64` em um diretório |
| `-b, --batch <FILES...>` | Decodifica múltiplos arquivos `.l64` |
| `-r, --recursive` | Percorre subdiretórios (usado com `--dir`) |
| `-o, --overwrite` | Sobrescreve arquivos de saída existentes |
| `-s, --source-code` | Decompila o bytecode para código-fonte Lua legível (Luau) |

### Exemplos

```sh
# Decodificar arquivo único (gera bytecode)
l6426 -f scripts/events.l64

# Decompilar para código-fonte legível
l6426 -f scripts/events.l64 -s

# Decompilar diretório inteiro, recursivo
l6426 -d scripts -r -o -s

# Batch de arquivos específicos
l6426 -b scripts/events.l64 scripts/game.l64 -s

# Somente decodificar (bytecode sem decompilação)
l6426 -d scripts -r -o
```

Os arquivos `.lua` são gerados no mesmo diretório do `.l64` original.

## Referências

- [Paint-a-Farm/lantern](https://github.com/Paint-a-Farm/lantern) — decompilador Luau usado internamente
- [scfmod/fs-utils](https://github.com/scfmod/fs-utils) — ferramenta de referência em Rust
- [chill1Penguin/l64decode](https://github.com/chill1Penguin/l64decode) — decoder em Python para FS19

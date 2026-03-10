# Atreus Shellcode Loader

**Atreus** is a shellcode loader wrapper for **[Kratos](https://github.com/Goultarde/kratos)** and other Mythic payloads.
Injects shellcode via Early Bird APC or thread hijacking with RC4/XOR encryption,
hash-based API resolution, ntdll unhook, ETW/AMSI patching, and sandbox detection.

### Installation
```bash
sudo ./mythic-cli install folder Atreus
```

### Usage
1. Build **Kratos** with `output_format = shellcode`.
2. Select **Atreus** as the wrapper for Kratos.
3. Configure injection technique, target process, and evasion options.
4. Deploy.

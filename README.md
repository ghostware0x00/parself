## About

- Built a low-level ELF binary analysis tool in C that parses ELF headers, program headers, and section headers manually without using external libraries. Supports both 32-bit and 64-bit ELF formats with proper endian handling and reconstructs binary metadata similar to Linux readelf.

## Usage

### Compilation

```bash
gcc parself.c -o parself
```

```bash
./parself <elf binary filename>
```

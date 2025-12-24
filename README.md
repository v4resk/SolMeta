# SolMeta - Solidity Metadata Extractor

A Python tool for extracting Solidity smart contract metadata from bytecode, including CBOR metadata and IPFS-based source information.

## Features

- Extract CBOR-encoded metadata from contract bytecode
- Fetch bytecode from RPC endpoints or local files
- Decode IPFS hashes from metadata
- Retrieve full metadata JSON from IPFS gateways
- JSON-only output mode for scripting and automation
- Supports both direct RPC queries and pre-fetched bytecode

## Installation

```bash
# Clone the repository
git clone https://github.com/v4resk/SolMeta
cd SolMeta

# Create and activate virtual environment
python -m venv venv
source venv/bin/activate  # Linux/Mac
# venv\Scripts\activate  # Windows

# Install dependencies
pip install -r requirements
```

## Usage

### Basic Commands

```bash
# Extract from RPC endpoint
python extract_metadata.py --rpc http://rpc.example.com --contract 0xContractAddress

# Extract from local bytecode file
python extract_metadata.py --file bytecode.txt

# JSON-only output (machine-readable)
python extract_metadata.py --rpc http://rpc.example.com --contract 0xContractAddress --json
python extract_metadata.py --file bytecode.txt --json

# Skip IPFS metadata fetch
python extract_metadata.py --rpc http://rpc.example.com --contract 0xContractAddress --no-ipfs
```

### Example Workflow

```bash
# 1. Fetch bytecode using cast (foundry)
cast code "0xDAa3Ab82Ce4fc5380AD68C83e198f79f66aAbA04" --rpc-url http://83.136.248.107:31160/ > bytecode.bin

# 2. Extract metadata from file
python extract_metadata.py --file bytecode.bin --json | jq
```

## Output Format

The tool provides structured output including:
- Contract bytecode length
- Decoded CBOR metadata (IPFS hash, compiler version)
- Solidity compiler information
- Full metadata JSON from IPFS (ABI, source info, compiler settings)

## License

MIT License - Free for commercial and personal use.
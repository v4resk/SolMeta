#!/usr/bin/env python3
"""
Solidity Metadata Extractor CLI Tool
Replicates the functionality of Sourcify Playground for extracting metadata from smart contracts.
"""

import argparse
import sys
import cbor2
import base58
import requests
from web3 import Web3
from typing import Optional, Dict, Any


# ANSI color codes for terminal output
class Colors:
    HEADER = "\033[95m"
    OKBLUE = "\033[94m"
    OKGREEN = "\033[92m"
    WARNING = "\033[93m"
    FAIL = "\033[91m"
    ENDC = "\033[0m"
    BOLD = "\033[1m"
    UNDERLINE = "\033[4m"

    @staticmethod
    def disable():
        Colors.HEADER = ""
        Colors.OKBLUE = ""
        Colors.OKGREEN = ""
        Colors.WARNING = ""
        Colors.FAIL = ""
        Colors.ENDC = ""
        Colors.BOLD = ""
        Colors.UNDERLINE = ""


def fetch_bytecode_from_rpc(rpc_url: str, contract_address: str) -> str:
    """
    Fetch bytecode from a blockchain node using RPC.

    Args:
        rpc_url: The RPC endpoint URL
        contract_address: The contract address to fetch bytecode from

    Returns:
        The contract bytecode as a hex string

    Raises:
        Exception: If connection fails or contract not found
    """
    try:
        # Initialize Web3 connection
        web3 = Web3(Web3.HTTPProvider(rpc_url))

        # Check if connected
        if not web3.is_connected():
            raise Exception(f"Failed to connect to RPC endpoint: {rpc_url}")

        # Validate address
        if not web3.is_address(contract_address):
            raise Exception(f"Invalid contract address: {contract_address}")

        # Convert to checksum address
        checksum_address = web3.to_checksum_address(contract_address)

        # Fetch bytecode
        bytecode = web3.eth.get_code(checksum_address)

        if bytecode == b"" or bytecode == b"\x00":
            raise Exception(f"No bytecode found at address: {contract_address}")

        # Convert to hex string and remove 0x prefix
        bytecode_hex = bytecode.hex()
        if bytecode_hex.startswith("0x"):
            bytecode_hex = bytecode_hex[2:]
        return bytecode_hex

    except Exception as e:
        raise Exception(f"Error fetching bytecode from RPC: {str(e)}")


def read_bytecode_from_file(filepath: str) -> str:
    """
    Read bytecode from a local file.

    Args:
        filepath: Path to the file containing bytecode

    Returns:
        The bytecode as a hex string

    Raises:
        Exception: If file cannot be read
    """
    try:
        with open(filepath, "r") as f:
            bytecode = f.read().strip()

        # Remove '0x' prefix if present
        if bytecode.startswith("0x"):
            bytecode = bytecode[2:]

        # Validate it's valid hex
        try:
            bytes.fromhex(bytecode)
        except ValueError:
            raise Exception("File does not contain valid hexadecimal bytecode")

        return bytecode

    except FileNotFoundError:
        raise Exception(f"File not found: {filepath}")
    except Exception as e:
        raise Exception(f"Error reading bytecode from file: {str(e)}")


def extract_cbor_metadata(bytecode: str) -> Dict[str, Any]:
    """
    Extract and decode CBOR metadata from the end of the bytecode.

    Solidity appends CBOR-encoded metadata at the end of the bytecode.
    The format is: <bytecode><cbor-metadata><2-byte-length>

    Args:
        bytecode: The contract bytecode as a hex string

    Returns:
        Decoded CBOR metadata as a dictionary

    Raises:
        Exception: If CBOR metadata cannot be extracted or decoded
    """
    try:
        # Convert hex string to bytes
        bytecode_bytes = bytes.fromhex(bytecode)

        # The last 2 bytes encode the length of the CBOR metadata
        if len(bytecode_bytes) < 2:
            raise Exception("Bytecode too short to contain metadata")

        # Read the length (big-endian, 2 bytes)
        metadata_length = int.from_bytes(bytecode_bytes[-2:], byteorder="big")

        # Extract the CBOR metadata (excluding the 2-byte length suffix)
        if len(bytecode_bytes) < metadata_length + 2:
            raise Exception(
                f"Bytecode length mismatch: expected at least {metadata_length + 2} bytes"
            )

        cbor_metadata_bytes = bytecode_bytes[-(metadata_length + 2) : -2]

        # Decode CBOR
        metadata = cbor2.loads(cbor_metadata_bytes)

        return metadata

    except cbor2.CBORDecodeError as e:
        raise Exception(f"Failed to decode CBOR metadata: {str(e)}")
    except Exception as e:
        raise Exception(f"Error extracting metadata: {str(e)}")


def decode_ipfs_hash(ipfs_bytes: bytes) -> str:
    """
    Decode IPFS hash from bytes to CIDv0 string.

    Args:
        ipfs_bytes: The IPFS hash as bytes

    Returns:
        The IPFS hash as a base58-encoded string (CIDv0 format)
    """
    try:
        # For CIDv0 (most common), add the multihash prefix
        # 0x12 = SHA-256, 0x20 = 32 bytes length
        if len(ipfs_bytes) == 32:
            multihash = b"\x12\x20" + ipfs_bytes
            return base58.b58encode(multihash).decode("utf-8")
        else:
            # Try direct encoding
            return base58.b58encode(ipfs_bytes).decode("utf-8")
    except Exception as e:
        raise Exception(f"Error decoding IPFS hash: {str(e)}")


def fetch_metadata_from_ipfs(
    ipfs_hash: str, timeout: int = 10
) -> Optional[Dict[str, Any]]:
    """
    Fetch metadata JSON from IPFS using public gateways.

    Args:
        ipfs_hash: The IPFS hash (CIDv0 format)
        timeout: Request timeout in seconds

    Returns:
        The metadata JSON as a dictionary, or None if fetch fails
    """
    # List of public IPFS gateways to try
    gateways = [
        f"https://ipfs.io/ipfs/{ipfs_hash}",
        f"https://gateway.pinata.cloud/ipfs/{ipfs_hash}",
        f"https://cloudflare-ipfs.com/ipfs/{ipfs_hash}",
    ]

    for gateway_url in gateways:
        try:
            response = requests.get(gateway_url, timeout=timeout)
            if response.status_code == 200:
                return response.json()
        except Exception:
            continue

    return None


def parse_compiler_version(metadata: Dict[str, Any]) -> Optional[str]:
    """
    Extract the Solidity compiler version from metadata.

    Args:
        metadata: The decoded CBOR metadata

    Returns:
        The compiler version string, or None if not found
    """
    # Common keys where compiler version might be stored
    if "solc" in metadata:
        solc_version = metadata["solc"]
        if isinstance(solc_version, bytes):
            return solc_version.decode("utf-8")
        return str(solc_version)

    return None


def print_results(
    bytecode: str,
    metadata: Dict[str, Any],
    ipfs_hash: Optional[str],
    metadata_json: Optional[Dict[str, Any]],
):
    """
    Print the extraction results in a readable format with colorized output.

    Args:
        bytecode: The contract bytecode
        metadata: The decoded CBOR metadata
        ipfs_hash: The IPFS hash of the metadata
        metadata_json: The metadata JSON from IPFS (if fetched)
    """
    print(f"\n{Colors.HEADER}{Colors.BOLD}" + "=" * 70)
    print("SOLIDITY METADATA EXTRACTION RESULTS")
    print("=" * 70 + f"{Colors.ENDC}")

    # Bytecode length
    print(
        f"\n{Colors.BOLD}[*] Contract Bytecode Length:{Colors.ENDC} {len(bytecode) // 2} bytes ({len(bytecode)} hex chars)"
    )

    # CBOR metadata
    print(f"\n{Colors.BOLD}[*] CBOR Decoded Metadata:{Colors.ENDC}")
    for key, value in metadata.items():
        if isinstance(value, bytes):
            # Display bytes as hex
            print(f"    {Colors.OKBLUE}{key}:{Colors.ENDC} 0x{value.hex()}")
        else:
            print(f"    {Colors.OKBLUE}{key}:{Colors.ENDC} {value}")

    # Compiler version
    compiler_version = parse_compiler_version(metadata)
    if compiler_version:
        print(
            f"\n{Colors.BOLD}[*] Solidity Compiler Version:{Colors.ENDC} {compiler_version}"
        )
    else:
        print(
            f"\n{Colors.BOLD}[*] Solidity Compiler Version:{Colors.ENDC} {Colors.WARNING}Not found in metadata{Colors.ENDC}"
        )

    # IPFS hash
    if ipfs_hash:
        print(f"\n{Colors.BOLD}[*] Metadata IPFS Hash:{Colors.ENDC} {ipfs_hash}")
        print(
            f"    {Colors.OKBLUE}Gateway URL:{Colors.ENDC} https://ipfs.io/ipfs/{ipfs_hash}"
        )
    else:
        print(
            f"\n{Colors.BOLD}[*] Metadata IPFS Hash:{Colors.ENDC} {Colors.WARNING}Not found in metadata{Colors.ENDC}"
        )

    # Metadata JSON from IPFS
    if metadata_json:
        print(f"\n{Colors.BOLD}[*] Metadata JSON from IPFS:{Colors.ENDC}")
        import json

        print(json.dumps(metadata_json, indent=2))
    elif ipfs_hash:
        print(
            f"\n{Colors.BOLD}[*] Metadata JSON from IPFS:{Colors.ENDC} {Colors.WARNING}Failed to fetch (gateways may be slow or unavailable){Colors.ENDC}"
        )

    print(f"\n{Colors.HEADER}{Colors.BOLD}" + "=" * 70 + f"{Colors.ENDC}\n")


def main():
    """
    Main CLI entry point.
    """
    parser = argparse.ArgumentParser(
        description="Extract Solidity metadata from smart contract bytecode",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Fetch from RPC
  python extract_metadata.py --rpc https://eth.llamarpc.com --contract 0x1234...

  # Read from file
  python extract_metadata.py --file bytecode.txt
        """,
    )

    # Create mutually exclusive group for input mode
    input_group = parser.add_mutually_exclusive_group(required=True)

    input_group.add_argument(
        "--rpc", type=str, help="RPC URL to fetch bytecode from blockchain"
    )

    input_group.add_argument(
        "--file", type=str, help="Path to local file containing bytecode"
    )

    parser.add_argument(
        "--contract", type=str, help="Contract address (required when using --rpc)"
    )

    parser.add_argument(
        "--no-ipfs", action="store_true", help="Skip fetching metadata JSON from IPFS"
    )

    parser.add_argument(
        "--json",
        action="store_true",
        help="Output only the metadata JSON (silent on success, errors still shown)",
    )

    args = parser.parse_args()

    # Validate argument combinations
    if args.rpc and not args.contract:
        parser.error("--contract is required when using --rpc")

    if args.contract and not args.rpc:
        parser.error("--contract can only be used with --rpc")

    try:
        # JSON mode - completely silent except for final JSON or errors
        if args.json:
            # Step 1: Get bytecode
            if args.rpc:
                bytecode = fetch_bytecode_from_rpc(args.rpc, args.contract)
            else:
                bytecode = read_bytecode_from_file(args.file)

            # Step 2: Extract CBOR metadata
            metadata = extract_cbor_metadata(bytecode)

            # Step 3: Decode IPFS hash
            ipfs_hash = None
            if "ipfs" in metadata:
                ipfs_bytes = metadata["ipfs"]
                if isinstance(ipfs_bytes, bytes):
                    ipfs_hash = decode_ipfs_hash(ipfs_bytes)

            # Step 4: Fetch metadata from IPFS (required in JSON mode)
            if not ipfs_hash:
                print("Error: No IPFS hash found in metadata", file=sys.stderr)
                return 1

            metadata_json = fetch_metadata_from_ipfs(ipfs_hash)
            if not metadata_json:
                print("Error: Could not fetch metadata JSON from IPFS", file=sys.stderr)
                return 1

            # Output only the JSON
            import json

            print(json.dumps(metadata_json))
            return 0

        # Regular mode - with progress messages and colorized output
        else:
            # Step 1: Get bytecode
            print(f"\n{Colors.OKBLUE}[1/4]{Colors.ENDC} Fetching bytecode...")
            if args.rpc:
                bytecode = fetch_bytecode_from_rpc(args.rpc, args.contract)
                print(
                    f"      {Colors.OKGREEN}✓ Successfully fetched bytecode from RPC{Colors.ENDC}"
                )
            else:
                bytecode = read_bytecode_from_file(args.file)
                print(
                    f"      {Colors.OKGREEN}✓ Successfully read bytecode from file{Colors.ENDC}"
                )

            # Step 2: Extract CBOR metadata
            print(f"\n{Colors.OKBLUE}[2/4]{Colors.ENDC} Extracting CBOR metadata...")
            metadata = extract_cbor_metadata(bytecode)
            print(
                f"      {Colors.OKGREEN}✓ Successfully extracted and decoded CBOR metadata{Colors.ENDC}"
            )

            # Step 3: Decode IPFS hash
            print(f"\n{Colors.OKBLUE}[3/4]{Colors.ENDC} Decoding IPFS hash...")
            ipfs_hash = None
            if "ipfs" in metadata:
                ipfs_bytes = metadata["ipfs"]
                if isinstance(ipfs_bytes, bytes):
                    ipfs_hash = decode_ipfs_hash(ipfs_bytes)
                    print(
                        f"      {Colors.OKGREEN}✓ IPFS hash: {ipfs_hash}{Colors.ENDC}"
                    )
                else:
                    print(
                        f"      {Colors.WARNING}⚠ Warning: IPFS field found but not in expected format{Colors.ENDC}"
                    )
            else:
                print(
                    f"      {Colors.WARNING}⚠ Warning: No IPFS hash found in metadata{Colors.ENDC}"
                )

            # Step 4: Fetch metadata from IPFS (optional)
            metadata_json = None
            print(
                f"\n{Colors.OKBLUE}[4/4]{Colors.ENDC} Fetching metadata JSON from IPFS..."
            )
            if ipfs_hash and not args.no_ipfs:
                metadata_json = fetch_metadata_from_ipfs(ipfs_hash)
                if metadata_json:
                    print(
                        f"      {Colors.OKGREEN}✓ Successfully fetched metadata from IPFS{Colors.ENDC}"
                    )
                else:
                    print(
                        f"      {Colors.WARNING}⚠ Warning: Could not fetch metadata from IPFS gateways{Colors.ENDC}"
                    )
            else:
                print(f"      Skipping IPFS fetch")

            print_results(bytecode, metadata, ipfs_hash, metadata_json)

        return 0

    except Exception as e:
        print(
            f"\n{Colors.FAIL}{Colors.BOLD}[ERROR]{Colors.ENDC} {str(e)}",
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    sys.exit(main())

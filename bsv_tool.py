import struct
import hashlib
import base64
import lz4.frame
import os
import json
import argparse
import xxhash
from dataclasses import dataclass, asdict
from typing import List, Optional, Tuple, Dict, Any

# ==============================================================================
# 1. Manifest Data Structures
# ==============================================================================

# A mapping of Line Handlers to their binary schema definition.
# This is used when writing BSV files with the "schema" format.
SCHEMA_DEFINITIONS = {
    'FullLineHandler': {
        'version': 16,
        'count': 6,
        'data': b'\x40\x40\x11\x11\x12\x21\x08'  # name, deps, group, priority, size, checksum
    },
    'LegacyFullLineHandler': {
        'version': 16,
        'count': 5,
        'data': b'\x40\x40\x11\x12\x21\x08'  # name, deps, group, size, checksum
    },
    'SimplifiedLineHandler': {
        'version': 16,
        'count': 3,
        'data': b'\x40\x12\x21\x08'  # name, size, checksum
    }
}

@dataclass
class ManifestEntry:
    """Represents a single entry in a manifest file."""
    name: bytes
    deps: Optional[bytes] = None
    group: int = 0
    priority: int = 0
    size: int = 0
    checksum: int = 0
    hname: Optional[str] = None
    kind: int = 0
    
    @property
    def tname(self) -> str:
        return self.name.decode('utf-8')

    @property
    def tdeps(self) -> Optional[str]:
        return self.deps.decode('utf-8') if self.deps else ""

    def to_dict(self):
        """Converts the entry to a JSON-serializable dictionary."""
        return asdict(self, dict_factory=lambda x: {k: v for (k, v) in x if k not in ['name', 'deps']}) | {'name': self.tname, 'deps': self.tdeps}
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]):
        """Creates a ManifestEntry from a dictionary (e.g., from JSON)."""
        return cls(
            name=data['name'].encode('utf-8'),
            deps=data['deps'].encode('utf-8') if data.get('deps') else b'',
            group=data.get('group', 0),
            priority=data.get('priority', 0),
            size=data.get('size', 0),
            checksum=data.get('checksum', 0),
            hname=data.get('hname'),
            kind=data.get('kind', 0)
        )

# ==============================================================================
# 2. H-Name and Checksum Calculation
# ==============================================================================

PREFIX_TO_STRIP = b'\x21\x08'

def strip_name_prefix(name: bytes) -> bytes:
    if name.startswith(PREFIX_TO_STRIP):
        return name[len(PREFIX_TO_STRIP):]
    return name

def calculate_hname(checksum: int, size: int, name: bytes) -> str:
    """Calculates the Base32-encoded SHA-1 hash for a manifest entry."""
    checksum_bytes = checksum.to_bytes(8, 'big', signed=False)
    size_bytes = size.to_bytes(8, 'big', signed=False)
    data_to_hash = checksum_bytes + size_bytes + name
    sha1_hash = hashlib.sha1(data_to_hash).digest()
    base32_string = base64.b32encode(sha1_hash).decode('ascii').rstrip('=')
    return base32_string

# ==============================================================================
# 3. Primitive Readers & Writers
# ==============================================================================

# --- Readers ---
def read_vlq(buffer: bytes, offset: int) -> Tuple[int, int]:
    n = 0
    for i in range(8):
        byte = buffer[offset]
        offset += 1
        n = (n << 7) | (byte & 0x7F)
        if (byte & 0x80) == 0:
            return offset, n
    return offset, n

def read_unum(buffer: bytes, offset: int, size: int) -> Tuple[int, int]:
    data = buffer[offset : offset + size]
    offset += size
    formats = {8: '>Q', 4: '>I', 2: '>H', 1: '>B'}
    if size not in formats:
        raise ValueError(f"Unsupported UNUM size: {size}")
    return offset, struct.unpack(formats[size], data)[0]

def read_text(buffer: bytes, offset: int) -> Tuple[int, bytes]:
    start = offset
    while offset < len(buffer) and buffer[offset] != 0:
        offset += 1
    text_bytes = buffer[start:offset]
    if offset < len(buffer) and buffer[offset] == 0:
        offset += 1
    return offset, text_bytes

# --- Writers ---
def write_vlq(n: int) -> bytes:
    if n == 0: return b'\x00'
    result = bytearray()
    result.append(n & 0x7F)
    n >>= 7
    while n > 0:
        result.append((n & 0x7F) | 0x80)
        n >>= 7
    result.reverse()
    return bytes(result)

def write_unum(n: int, size: int) -> bytes:
    formats = {8: '>Q', 4: '>I', 2: '>H', 1: '>B'}
    if size not in formats:
        raise ValueError(f"Unsupported UNUM size: {size}")
    return struct.pack(formats[size], n)

def write_text(b: bytes) -> bytes:
    return b + b'\x00'

# ==============================================================================
# 4. Line Parsers & Serializers
# ==============================================================================

class BaseLineHandler:
    def parse(self, buffer: bytes, offset: int) -> Tuple[int, Dict[str, Any]]:
        raise NotImplementedError
    def serialize(self, entry: ManifestEntry) -> bytes:
        raise NotImplementedError

class SimplifiedLineHandler(BaseLineHandler):
    def parse(self, buffer, offset):
        dat = {}
        offset, dat['name'] = read_text(buffer, offset)
        offset, dat['size'] = read_vlq(buffer, offset)
        offset, dat['checksum'] = read_unum(buffer, offset, 8)
        return offset, dat
    def serialize(self, entry):
        return b''.join([
            write_text(entry.name),
            write_vlq(entry.size),
            write_unum(entry.checksum, 8)
        ])

class FullLineHandler(BaseLineHandler):
    def parse(self, buffer, offset):
        dat = {}
        offset, dat['name'] = read_text(buffer, offset)
        offset, dat['deps'] = read_text(buffer, offset)
        offset, dat['group'] = read_vlq(buffer, offset)
        offset, dat['priority'] = read_vlq(buffer, offset)
        offset, dat['size'] = read_vlq(buffer, offset)
        offset, dat['checksum'] = read_unum(buffer, offset, 8)
        return offset, dat
    def serialize(self, entry):
        return b''.join([
            write_text(entry.name),
            write_text(entry.deps or b''),
            write_vlq(entry.group),
            write_vlq(entry.priority),
            write_vlq(entry.size),
            write_unum(entry.checksum, 8)
        ])

class LegacyFullLineHandler(FullLineHandler):
    def parse(self, buffer, offset):
        offset, dat = super().parse(buffer, offset)
        dat['priority'] = 0 # Not present in legacy format
        return offset, dat
    def serialize(self, entry):
        # Legacy format doesn't include priority
        return b''.join([
            write_text(entry.name),
            write_text(entry.deps or b''),
            write_vlq(entry.group),
            write_vlq(entry.size),
            write_unum(entry.checksum, 8)
        ])

# ==============================================================================
# 5. BSV Reader/Writer Classes
# ==============================================================================

class BaseBSVReader:
    def __init__(self, buffer: bytes, start_offset: int):
        self.buffer = buffer
        self.offset = start_offset
        self.row_count = 0

    def read_all_entries(self, parser: BaseLineHandler) -> List[ManifestEntry]:
        """Reads all rows and correctly handles name prefixes for hname calculation."""
        entries = []
        for _ in range(self.row_count):
            self.offset, data = parser.parse(self.buffer, self.offset)
            
            # \x21\x08 got treated wrongly
            clean_name = strip_name_prefix(data['name'])
            data['hname'] = calculate_hname(data['checksum'], data['size'], clean_name)
            
            # Store the clean name in the final entry object to match the database representation.
            data['name'] = clean_name
            
            entries.append(ManifestEntry(**data))
        return entries

class AprioriBSVReader(BaseBSVReader):
    def __init__(self, buffer: bytes, start_offset: int):
        super().__init__(buffer, start_offset)
        self.offset, self.row_count = read_vlq(self.buffer, self.offset)
        self.offset, _ = read_vlq(self.buffer, self.offset) # max_row_size
        print(f"INFO: Apriori Reader initialized. Rows: {self.row_count}")

class AnonymousSchemaBSVReader(BaseBSVReader):
    def __init__(self, buffer: bytes, start_offset: int):
        super().__init__(buffer, start_offset)
        self.offset, header_size = read_unum(self.buffer, self.offset, 2)
        self.offset, self.row_count = read_vlq(self.buffer, self.offset)
        # The actual data starts after the full header, so we jump the offset there.
        self.offset = start_offset + header_size
        print(f"INFO: AnonymousSchema Reader initialized. Rows: {self.row_count}")

def init_bsv_reader(filepath: str) -> BaseBSVReader:
    try:
        with open(filepath, 'rb') as f_in:
            buffer = lz4.frame.decompress(f_in.read())
    except Exception as e:
        raise IOError(f"Failed to decompress LZ4 file '{filepath}': {e}")
        
    if buffer[0] != 0xBF: raise ValueError("BSV magic mismatch")
    version, format_id = buffer[1] >> 4, buffer[1] & 0x0F
    if version != 1: raise ValueError("BSV version mismatch")
    print(f"INFO: BSV Header OK. Version: {version}, Format: {format_id}")
    if format_id == 0: return AprioriBSVReader(buffer, 2)
    if format_id == 1: return AnonymousSchemaBSVReader(buffer, 2)
    raise ValueError(f"BSV unsupported format: {format_id}")

# ==============================================================================
# 6. High-Level API & Main Logic
# ==============================================================================

def read_manifest(filepath: str, format_type: str = 'full') -> List[ManifestEntry]:
    reader = init_bsv_reader(filepath)
    parser: BaseLineHandler
    if format_type == 'simplified':
        parser = SimplifiedLineHandler()
    elif isinstance(reader, AprioriBSVReader):
        parser = LegacyFullLineHandler()
    else:
        parser = FullLineHandler()
    return reader.read_all_entries(parser)

def write_manifest(output_path: str, entries: List[ManifestEntry], line_handler: BaseLineHandler, bsv_format: str = 'schema'):
    print(f"INFO: Preparing to write {len(entries)} entries to '{output_path}'")
    
    # Serialize all rows first to calculate body size and max_row_size
    if not entries:
        serialized_rows = []
        max_row_size = 0
    else:
        serialized_rows = [line_handler.serialize(entry) for entry in entries]
        max_row_size = max(len(row) for row in serialized_rows)
        
    body_bytes = b''.join(serialized_rows)
    
    header_bytes = b''
    if bsv_format == 'apriori':
        header_bytes = b'\xBF\x10' # Magic + Version 1, Format 0
        header_bytes += write_vlq(len(entries)) # row_count
        header_bytes += write_vlq(max_row_size) # max_row_size
    elif bsv_format == 'schema':
        header_body = bytearray()
        header_body += write_vlq(len(entries)) # row_count
        header_body += write_vlq(max_row_size) # max_row_size
        
        # Look up schema definition based on the line handler being used
        handler_name = type(line_handler).__name__
        schema_info = SCHEMA_DEFINITIONS.get(handler_name)
        
        if schema_info:
            print(f"INFO: Found schema for {handler_name}. Writing full schema header.")
            header_body += write_vlq(schema_info['version']) # schema_version
            header_body += write_vlq(schema_info['count'])   # schema_count
            header_body += schema_info['data']               # schema_data
        else:
            print(f"WARNING: No schema definition for {handler_name}. Writing minimal header.")
            header_body += write_vlq(1) # schema_version (fallback)
            header_body += write_vlq(0) # schema_count (empty schema)
        
        header_bytes = b'\xBF\x11' # Magic + Version 1, Format 1
        header_bytes += write_unum(len(header_body), 2) # header_size
        header_bytes += header_body
    else:
        raise ValueError(f"Unknown BSV format for writing: {bsv_format}")

    final_buffer = header_bytes + body_bytes
    print(f"INFO: Uncompressed size: {len(final_buffer)} bytes")
    
    compressed_buffer = lz4.frame.compress(final_buffer)
    print(f"INFO: Compressed size: {len(compressed_buffer)} bytes")

    with open(output_path, 'wb') as f_out:
        f_out.write(compressed_buffer)

def main():
    parser = argparse.ArgumentParser(description="A tool to read and write Umamusume BSV manifest files.", formatter_class=argparse.RawTextHelpFormatter)
    subparsers = parser.add_subparsers(dest="command", required=True)

    # --- Read Command ---
    p_read = subparsers.add_parser("read", help="Read a BSV manifest and convert to JSON.")
    p_read.add_argument("filepath", help="Path to the compressed manifest file.")
    p_read.add_argument("-o", "--output", help="Path to save the output JSON file.")
    p_read.add_argument("-f", "--format", choices=['full', 'simplified'], default='full', help="The manifest format type to parse.")
    
    # --- Write Command ---
    p_write = subparsers.add_parser("write", help="Write a new BSV manifest from a JSON file.")
    p_write.add_argument("input_json", help="Path to the input JSON file.")
    p_write.add_argument("output_path", help="Path to write the new compressed manifest file.")
    p_write.add_argument("-f", "--format", choices=['full', 'simplified', 'legacy'], default='full', help="The manifest line format to use for writing.")
    p_write.add_argument("--bsv-format", choices=['schema', 'apriori'], default='schema', help="The overall BSV file structure (header type).")

    args = parser.parse_args()

    try:
        if args.command == 'read':
            entries = read_manifest(args.filepath, args.format)
            json_output = json.dumps([e.to_dict() for e in entries], indent=2, ensure_ascii=False)
            if args.output:
                with open(args.output, 'w', encoding='utf-8') as f: f.write(json_output)
                print(f"\nSUCCESS: Manifest read and saved to '{args.output}'")
            else:
                print("\n--- Manifest Contents ---")
                print(json_output)
        
        elif args.command == 'write':
            with open(args.input_json, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            entries = [ManifestEntry.from_dict(item) for item in data]
            
            # Recalculate hname for all entries to ensure they are correct
            for entry in entries:
                entry.hname = calculate_hname(entry.checksum, entry.size, entry.name)

            line_handlers = {'full': FullLineHandler(), 'simplified': SimplifiedLineHandler(), 'legacy': LegacyFullLineHandler()}
            handler = line_handlers[args.format]
            
            write_manifest(args.output_path, entries, handler, args.bsv_format)
            print(f"\nSUCCESS: Manifest written to '{args.output_path}'")

    except (IOError, ValueError, FileNotFoundError, json.JSONDecodeError) as e:
        print(f"\nERROR: {e}")
        exit(1)

if __name__ == '__main__':

    main()

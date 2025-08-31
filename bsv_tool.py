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
# Manifest Data Structures & Schema
# ==============================================================================

SCHEMA_DEFINITIONS = {
    'FullLineHandler': {
        'version': 16, 'count': 6, 'data': b'\x40\x40\x11\x11\x12\x21\x08'
    },
    'LegacyFullLineHandler': {
        'version': 16, 'count': 5, 'data': b'\x40\x40\x11\x12\x21\x08'
    },
    'SimplifiedLineHandler': {
        'version': 16, 'count': 3, 'data': b'\x40\x12\x21\x08'
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

# Python misunderstood this sometimes, so I just did this.
# Works for me, works for everyone...
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
        entries = []
        for _ in range(self.row_count):
            self.offset, data = parser.parse(self.buffer, self.offset)
            clean_name = strip_name_prefix(data['name'])
            data['hname'] = calculate_hname(data.get('checksum', 0), data.get('size', 0), clean_name)
            data['name'] = clean_name
            entries.append(ManifestEntry(**data))
        return entries

class AprioriBSVReader(BaseBSVReader):
    def __init__(self, buffer: bytes, start_offset: int):
        super().__init__(buffer, start_offset)
        self.offset, self.row_count = read_vlq(self.buffer, self.offset)
        self.offset, _ = read_vlq(self.buffer, self.offset)
        print("INFO: Apriori Reader initialized. Rows: {self.row_count}")

class AnonymousSchemaBSVReader(BaseBSVReader):
    def __init__(self, buffer: bytes, start_offset: int):
        super().__init__(buffer, start_offset)
        self.schema_count = 0
        self.schema_version = 0
        
        self.offset, _ = read_unum(self.buffer, self.offset, 2)
        self.offset, self.row_count = read_vlq(self.buffer, self.offset)
        self.offset, _ = read_vlq(self.buffer, self.offset)
        self.offset, self.schema_version = read_vlq(self.buffer, self.offset)
        self.offset, self.schema_count = read_vlq(self.buffer, self.offset)
        
        for _ in range(self.schema_count):
            self.offset, schema_type = read_unum(self.buffer, self.offset, 1)
            if ((schema_type - 33) & 0xCF) == 0 and schema_type != 81:
                self.offset, _ = read_vlq(self.buffer, self.offset)
        
        print(f"INFO: AnonymousSchema Reader initialized. Rows: {self.row_count}, Schema Columns: {self.schema_count}.")

def _init_reader_from_buffer(buffer: bytes) -> BaseBSVReader:
    """Internal helper to initialize a reader from a decompressed byte buffer."""
    if buffer[0] != 0xBF: raise ValueError("BSV magic mismatch")
    version, format_id = buffer[1] >> 4, buffer[1] & 0x0F
    if version != 1: raise ValueError("BSV version mismatch")
    print(f"INFO: BSV Header OK. Version: {version}, Format: {format_id}")
    if format_id == 0: return AprioriBSVReader(buffer, 2)
    if format_id == 1: return AnonymousSchemaBSVReader(buffer, 2)
    raise ValueError(f"BSV unsupported format: {format_id}")

def init_bsv_reader(filepath: str) -> BaseBSVReader:
    """Initializes a BSV reader from a file path."""
    try:
        with open(filepath, 'rb') as f_in:
            buffer = lz4.frame.decompress(f_in.read())
        return _init_reader_from_buffer(buffer)
    except Exception as e:
        raise IOError(f"Failed to read or decompress LZ4 file '{filepath}': {e}")

# ==============================================================================
# 6. High-Level API & Main Logic
# ==============================================================================

def read_manifest(source: str | bytes, format_type: str = 'auto') -> List[ManifestEntry]:
    """
    High-level function to read a manifest from a file path (str) or
    from in-memory compressed bytes.
    """
    reader: BaseBSVReader
    if isinstance(source, str):
        # If it's a string, treat it as a file path
        reader = init_bsv_reader(source)
    elif isinstance(source, bytes):
        # If it's bytes, decompress it and initialize from the buffer
        decompressed_buffer = lz4.frame.decompress(source)
        reader = _init_reader_from_buffer(decompressed_buffer)
    else:
        raise TypeError("source must be a file path (str) or compressed bytes.")
    
    if format_type == 'auto':
        print("INFO: Auto-detecting format...")
        if isinstance(reader, AnonymousSchemaBSVReader):
            if reader.schema_count == 3:
                format_type = 'simplified'
                print("INFO: Detected 3 schema columns -> 'simplified' format.")
            else:
                format_type = 'full'
                print(f"INFO: Detected {reader.schema_count} schema columns -> 'full' format.")
        else:
            format_type = 'legacy'
            print("INFO: Apriori BSV detected -> 'legacy' format.")

    if format_type == 'simplified':
        parser = SimplifiedLineHandler()
    elif format_type == 'legacy':
        parser = LegacyFullLineHandler()
    else: # 'full'
        parser = FullLineHandler()
        
    return reader.read_all_entries(parser)

def write_manifest(output_path: str, entries: List[ManifestEntry], line_handler: BaseLineHandler, bsv_format: str = 'schema'):
    print(f"INFO: Preparing to write {len(entries)} entries to '{output_path}'")
    
    if not entries:
        serialized_rows, max_row_size = [], 0
    else:
        serialized_rows = [line_handler.serialize(entry) for entry in entries]
        max_row_size = max(len(row) for row in serialized_rows)
        
    body_bytes = b''.join(serialized_rows)
    
    header_bytes = b''
    if bsv_format == 'apriori':
        header_bytes = b'\xBF\x10'
        header_bytes += write_vlq(len(entries))
        header_bytes += write_vlq(max_row_size)
    elif bsv_format == 'schema':
        header_body = bytearray()
        header_body += write_vlq(len(entries))
        header_body += write_vlq(max_row_size)
        
        handler_name = type(line_handler).__name__
        schema_info = SCHEMA_DEFINITIONS.get(handler_name)
        
        if schema_info:
            print(f"INFO: Found schema for {handler_name}. Writing full schema header.")
            header_body += write_vlq(schema_info['version'])
            header_body += write_vlq(schema_info['count'])
            header_body += schema_info['data']
        else:
            print(f"WARNING: No schema definition for {handler_name}. Writing minimal header.")
            header_body += write_vlq(1)
            header_body += write_vlq(0)
        
        header_bytes = b'\xBF\x11'
        header_bytes += write_unum(len(header_body), 2)
        header_bytes += header_body
    else:
        raise ValueError(f"Unknown BSV format for writing: {bsv_format}")

    final_buffer = header_bytes + body_bytes
    compressed_buffer = lz4.frame.compress(final_buffer)
    with open(output_path, 'wb') as f_out:
        f_out.write(compressed_buffer)

def main():
    parser = argparse.ArgumentParser(description="A tool to read and write Umamusume BSV manifest files.", formatter_class=argparse.RawTextHelpFormatter)
    subparsers = parser.add_subparsers(dest="command", required=True)

    p_read = subparsers.add_parser("read", help="Read a BSV manifest and convert to JSON.")
    p_read.add_argument("filepath", help="Path to the compressed manifest file.")
    p_read.add_argument("-o", "--output", help="Path to save the output JSON file.")
    p_read.add_argument("-f", "--format", choices=['auto', 'full', 'simplified'], default='auto', help="The manifest format type to parse. 'auto' is recommended.")
    
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
# SPDX-FileCopyrightText: 2023-2024 Sebastian Schrand
#                         2017-2022 Jens M. Plonka
#                         2005-2018 Philippe Lagadec
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Import is based on using information from `olefile` IO source-code
# and the FreeCAD Autodesk 3DS Max importer ImportMAX.
#
# `olefile` (formerly OleFileIO_PL) is copyright Philippe Lagadec.
# (https://www.decalage.info)
#
# ImportMAX is copyright Jens M. Plonka.
# (https://www.github.com/jmplonka/Importer3D)

import io
import os
import re
import sys
import bpy
import math
import zlib
import array
import struct
import mathutils
from pathlib import Path
from bpy_extras.image_utils import load_image
from bpy_extras.node_shader_utils import PrincipledBSDFWrapper


###################
# DATA STRUCTURES #
###################

MAGIC = b'\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1'
WORD_CLSID = "00020900-0000-0000-C000-000000000046"

MIN_FILE_SIZE = 1536
UNKNOWN_SIZE = 0x7FFFFFFF
MAXFILE_SIZE = 0x7FFFFFFFFFFFFFFF
MAXREGSECT = 0xFFFFFFFA  # (-6) maximum SECT
DIFSECT = 0xFFFFFFFC  # (-4) denotes a DIFAT sector in a FAT
FATSECT = 0xFFFFFFFD  # (-3) denotes a FAT sector in a FAT
ENDOFCHAIN = 0xFFFFFFFE  # (-2) end of a virtual stream chain
FREESECT = 0xFFFFFFFF  # (-1) unallocated sector
MAX_STREAM = 2  # element is a stream object
ROOT_STORE = 5  # element is a root storage

TYP_VALUE = {0x100, 0x2513}
TYP_REFS = {0x1040, 0x2034, 0x2035}
TYP_LINK = {0x1020, 0x1030, 0x1050, 0x1080, 0x3002, 0x4003}
TYP_NAME = {0x340, 0x456, 0x962, 0x10A0, 0x1010, 0x1230, 0x4001}
TYP_ARRAY = {0x96A, 0x96B, 0x96C, 0x2501, 0x2503, 0x2504, 0x2505, 0x2511}
UNPACK_BOX_DATA = struct.Struct('<HIHHBff').unpack_from  # Index, int, 2short, byte, 2float
INVALID_NAME = re.compile('^[0-9].*')

FLOAT_POINT = 0x71F11549498702E7  # Float Wire
MATRIX_POS = 0xFFEE238A118F7E02  # Position XYZ
MATRIX_ROT = 0x3A90416731381913  # Rotation Wire
MATRIX_SCL = 0xFEEE238B118F7C01  # Scale XYZ
BIPED_OBJ = 0x0000000000009125  # Biped Object
BIPED_ANIM = 0x78C6B2A6B147369  # Biped SubAnim
EDIT_MESH = 0x00000000E44F10B3  # Editable Mesh
EDIT_POLY = 0x192F60981BF8338D  # Editable Poly
POLY_MESH = 0x000000005D21369A  # PolyMeshObject
CORO_MTL = 0x448931DD70BE6506  # CoronaMtl
ARCH_MTL = 0x4A16365470B05735  # ArchMtl
VRAY_MTL = 0x7034695C37BF3F2F  # VRayMtl
DUMMY = 0x0000000000876234  # Dummy
PLANE = 0x77566F65081F1DFC  # Plane
CONE = 0x00000000A86C23DD  # Cone

SKIPPABLE = {
    0x0000000000001002: 'Camera',
    0x0000000000001011: 'Omni',
    0x0000000000001013: 'Free Direct',
    0x0000000000001020: 'Camera Target',
    0x0000000000001040: 'Line',
    0x0000000000001065: 'Rectangle',
    0x0000000000001097: 'Ellipse',
    0x0000000000001999: 'Circle',
    0x0000000000002013: 'Point',
    0x05622B0D69011E82: 'Compass',
    0x12A822FB76A11646: 'CV Surface',
    0x1EB3430074F93B07: 'Particle View',
    0x2ECCA84028BF6E8D: 'Bone',
    0x3BDB0E0C628140F6: 'VRayPlane',
    0x4E9B599047DB14EF: 'Slider',
    0x522E47057BF61478: 'Sky',
    0x5FD602DF3C5575A1: 'VRayLight',
}

CONFIG = []
CLS_DATA = []
DLL_DIR_LIST = []
CLS_DIR3_LIST = []
VID_PST_QUE = []
SCENE_LIST = []

object_list = []
object_dict = {}
parent_dict = {}
matrix_dict = {}


def get_valid_name(name):
    if (INVALID_NAME.match(name)):
        return "_%s" % (name.encode('utf8'))
    return "%s" % (name.encode('utf8'))


def i8(data):
    return data if data.__class__ is int else data[0]


def i16(data, offset=0):
    return struct.unpack("<H", data[offset:offset + 2])[0]


def i32(data, offset=0):
    return struct.unpack("<I", data[offset:offset + 4])[0]


def get_byte(data, offset=0):
    size = offset + 1
    value = struct.unpack('<B', data[offset:size])[0]
    return value, size


def get_short(data, offset=0):
    size = offset + 2
    value = struct.unpack('<H', data[offset:size])[0]
    return value, size


def get_long(data, offset=0):
    size = offset + 4
    value = struct.unpack('<I', data[offset:size])[0]
    return value, size


def get_float(data, offset=0):
    size = offset + 4
    value = struct.unpack('<f', data[offset:size])[0]
    return value, size


def get_bytes(data, offset=0, count=1):
    size = offset + count
    values = struct.unpack('<' + 'B' * count, data[offset:size])
    return values, size


def get_shorts(data, offset=0, count=1):
    size = offset + count * 2
    values = struct.unpack('<' + 'H' * count, data[offset:size])
    return values, size


def get_longs(data, offset=0, count=1):
    size = offset + count * 4
    values = struct.unpack('<' + 'I' * count, data[offset:size])
    return values, size


def get_floats(data, offset=0, count=1):
    size = offset + count * 4
    values = struct.unpack('<' + 'f' * count, data[offset:size])
    return values, size


def _clsid(clsid):
    """Converts a CLSID to a readable string."""
    assert len(clsid) == 16
    if not clsid.strip(b"\0"):
        return ""
    return (("%08X-%04X-%04X-%02X%02X-" + "%02X" * 6) %
            ((i32(clsid, 0), i16(clsid, 4), i16(clsid, 6)) +
            tuple(map(i8, clsid[8:16]))))


###############
# DATA IMPORT #
###############

def is_maxfile(filename):
    """Test if file is a MAX OLE2 container."""
    if hasattr(filename, 'read'):
        header = filename.read(len(MAGIC))
        filename.seek(0)
    elif isinstance(filename, bytes) and len(filename) >= MIN_FILE_SIZE:
        header = filename[:len(MAGIC)]
    else:
        with open(filename, 'rb') as fp:
            header = fp.read(len(MAGIC))
    if header == MAGIC:
        return True
    else:
        return False


class MaxStream(io.BytesIO):
    """Returns an instance of the BytesIO class as read-only file object."""

    def __init__(self, fp, sect, size, offset, sectorsize, fat, filesize):
        if size == UNKNOWN_SIZE:
            size = len(fat) * sectorsize
        nb_sectors = (size + (sectorsize - 1)) // sectorsize

        data = []
        for i in range(nb_sectors):
            try:
                fp.seek(offset + sectorsize * sect)
            except:
                break
            sector_data = fp.read(sectorsize)
            data.append(sector_data)
            try:
                sect = fat[sect] & FREESECT
            except IndexError:
                break
        data = b"".join(data)
        if len(data) >= size:
            data = data[:size]
            self.size = size
        else:
            self.size = len(data)
        io.BytesIO.__init__(self, data)


class MaxFileDirEntry:
    """Directory Entry for a stream or storage."""
    STRUCT_DIRENTRY = '<64sHBBIII16sIQQIII'
    DIRENTRY_SIZE = 128
    assert struct.calcsize(STRUCT_DIRENTRY) == DIRENTRY_SIZE

    def __init__(self, entry, sid, maxfile):
        self.sid = sid
        self.maxfile = maxfile
        self.kids = []
        self.kids_dict = {}
        self.used = False
        (
            self.name_raw,
            self.namelength,
            self.entry_type,
            self.color,
            self.sid_left,
            self.sid_right,
            self.sid_child,
            clsid,
            self.dwUserFlags,
            self.createTime,
            self.modifyTime,
            self.isectStart,
            self.sizeLow,
            self.sizeHigh
        ) = struct.unpack(MaxFileDirEntry.STRUCT_DIRENTRY, entry)

        if self.namelength > 64:
            self.namelength = 64
        self.name_utf16 = self.name_raw[:(self.namelength - 2)]
        self.name = maxfile._decode_utf16_str(self.name_utf16)
        # print('DirEntry SID=%d: %s' % (self.sid, repr(self.name)))
        if maxfile.sectorsize == 512:
            self.size = self.sizeLow
        else:
            self.size = self.sizeLow + (int(self.sizeHigh) << 32)
        self.clsid = _clsid(clsid)
        self.is_minifat = False
        if self.entry_type in (ROOT_STORE, MAX_STREAM) and self.size > 0:
            if self.size < maxfile.minisectorcutoff \
                    and self.entry_type == MAX_STREAM:  # only streams can be in MiniFAT
                self.is_minifat = True
            else:
                self.is_minifat = False
            maxfile._check_duplicate_stream(self.isectStart, self.is_minifat)
        self.sect_chain = None

    def build_sect_chain(self, maxfile):
        if self.sect_chain:
            return
        if self.entry_type not in (ROOT_STORE, MAX_STREAM) or self.size == 0:
            return
        self.sect_chain = list()
        if self.is_minifat and not maxfile.minifat:
            maxfile.loadminifat()
        next_sect = self.isectStart
        while next_sect != ENDOFCHAIN:
            self.sect_chain.append(next_sect)
            if self.is_minifat:
                next_sect = maxfile.minifat[next_sect]
            else:
                next_sect = maxfile.fat[next_sect]

    def build_storage_tree(self):
        if self.sid_child != FREESECT:
            self.append_kids(self.sid_child)
            self.kids.sort()

    def append_kids(self, child_sid):
        if child_sid == FREESECT:
            return
        else:
            child = self.maxfile._load_direntry(child_sid)
            if child.used:
                return
            child.used = True
            self.append_kids(child.sid_left)
            name_lower = child.name.lower()
            self.kids.append(child)
            self.kids_dict[name_lower] = child
            self.append_kids(child.sid_right)
            child.build_storage_tree()

    def __eq__(self, other):
        return self.name == other.name

    def __lt__(self, other):
        return self.name < other.name

    def __ne__(self, other):
        return not self.__eq__(other)

    def __le__(self, other):
        return self.__eq__(other) or self.__lt__(other)


class ImportMaxFile:
    """Representing an interface for importing .max files."""

    def __init__(self, filename=None):
        self._filesize = None
        self.byte_order = None
        self.directory_fp = None
        self.direntries = None
        self.dll_version = None
        self.fat = None
        self.first_difat_sector = None
        self.first_dir_sector = None
        self.first_mini_fat_sector = None
        self.fp = None
        self.header_clsid = None
        self.header_signature = None
        self.mini_sector_shift = None
        self.mini_sector_size = None
        self.mini_stream_cutoff_size = None
        self.minifat = None
        self.minifatsect = None
        self.minisectorcutoff = None
        self.minisectorsize = None
        self.ministream = None
        self.minor_version = None
        self.nb_sect = None
        self.num_difat_sectors = None
        self.num_dir_sectors = None
        self.num_fat_sectors = None
        self.num_mini_fat_sectors = None
        self.reserved1 = None
        self.reserved2 = None
        self.root = None
        self.sector_shift = None
        self.sector_size = None
        self.transaction_signature_number = None
        if filename:
            self.open(filename)

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    def _decode_utf16_str(self, utf16_str, errors='replace'):
        unicode_str = utf16_str.decode('UTF-16LE', errors)
        return unicode_str

    def open(self, filename):
        if hasattr(filename, 'read'):
            self.fp = filename
        elif isinstance(filename, bytes) and len(filename) >= MIN_FILE_SIZE:
            self.fp = io.BytesIO(filename)
        else:
            self.fp = open(filename, 'rb')
        filesize = 0
        self.fp.seek(0, os.SEEK_END)
        try:
            filesize = self.fp.tell()
        finally:
            self.fp.seek(0)
        self._filesize = filesize
        self._used_streams_fat = []
        self._used_streams_minifat = []
        header = self.fp.read(512)
        fmt_header = '<8s16sHHHHHHLLLLLLLLLL'
        header_size = struct.calcsize(fmt_header)
        header1 = header[:header_size]
        (
            self.header_signature,
            self.header_clsid,
            self.minor_version,
            self.dll_version,
            self.byte_order,
            self.sector_shift,
            self.mini_sector_shift,
            self.reserved1,
            self.reserved2,
            self.num_dir_sectors,
            self.num_fat_sectors,
            self.first_dir_sector,
            self.transaction_signature_number,
            self.mini_stream_cutoff_size,
            self.first_mini_fat_sector,
            self.num_mini_fat_sectors,
            self.first_difat_sector,
            self.num_difat_sectors
        ) = struct.unpack(fmt_header, header1)

        self.sector_size = 2**self.sector_shift
        self.mini_sector_size = 2**self.mini_sector_shift
        if self.mini_stream_cutoff_size != 0x1000:
            self.mini_stream_cutoff_size = 0x1000
        self.nb_sect = ((filesize + self.sector_size - 1) // self.sector_size) - 1

        # file clsid
        self.header_clsid = _clsid(header[8:24])
        self.sectorsize = self.sector_size  # i16(header, 30)
        self.minisectorsize = self.mini_sector_size   # i16(header, 32)
        self.minisectorcutoff = self.mini_stream_cutoff_size  # i32(header, 56)
        self._check_duplicate_stream(self.first_dir_sector)
        if self.num_mini_fat_sectors:
            self._check_duplicate_stream(self.first_mini_fat_sector)
        if self.num_difat_sectors:
            self._check_duplicate_stream(self.first_difat_sector)

        # Load file allocation tables
        self.loadfat(header)
        self.loaddirectory(self.first_dir_sector)
        self.minifatsect = self.first_mini_fat_sector

    def close(self):
        self.fp.close()

    def _check_duplicate_stream(self, first_sect, minifat=False):
        if minifat:
            used_streams = self._used_streams_minifat
        else:
            if first_sect in (DIFSECT, FATSECT, ENDOFCHAIN, FREESECT):
                return
            used_streams = self._used_streams_fat
        if first_sect in used_streams:
            pass
        else:
            used_streams.append(first_sect)

    def sector_array(self, sect):
        ary = array.array('I', sect)
        if sys.byteorder == 'big':
            ary.byteswap()
        return ary

    def loadfat_sect(self, sect):
        if isinstance(sect, array.array):
            fat1 = sect
        else:
            fat1 = self.sector_array(sect)
        isect = None
        for isect in fat1:
            isect = isect & FREESECT
            if isect == ENDOFCHAIN or isect == FREESECT:
                break
            sector = self.getsect(isect)
            nextfat = self.sector_array(sector)
            self.fat = self.fat + nextfat
        return isect

    def loadfat(self, header):
        sect = header[76:512]
        self.fat = array.array('I')
        self.loadfat_sect(sect)
        if self.num_difat_sectors != 0:
            nb_difat_sectors = (self.sectorsize // 4) - 1
            nb_difat = (self.num_fat_sectors - 109 + nb_difat_sectors - 1) // nb_difat_sectors
            isect_difat = self.first_difat_sector
            for i in range(nb_difat):
                sector_difat = self.getsect(isect_difat)
                difat = self.sector_array(sector_difat)
                self.loadfat_sect(difat[:nb_difat_sectors])
                isect_difat = difat[nb_difat_sectors]
        if len(self.fat) > self.nb_sect:
            self.fat = self.fat[:self.nb_sect]

    def loadminifat(self):
        stream_size = self.num_mini_fat_sectors * self.sector_size
        nb_minisectors = (self.root.size + self.mini_sector_size - 1) // self.mini_sector_size
        used_size = nb_minisectors * 4
        sect = self._open(self.minifatsect, stream_size, force_FAT=True).read()
        self.minifat = self.sector_array(sect)
        self.minifat = self.minifat[:nb_minisectors]

    def getsect(self, sect):
        try:
            self.fp.seek(self.sectorsize * (sect + 1))
        except:
            print('IndexError: Sector index out of range')
        sector = self.fp.read(self.sectorsize)
        return sector

    def loaddirectory(self, sect):
        self.directory_fp = self._open(sect, force_FAT=True)
        max_entries = self.directory_fp.size // 128
        self.direntries = [None] * max_entries
        root_entry = self._load_direntry(0)
        self.root = self.direntries[0]
        self.root.build_storage_tree()

    def _load_direntry(self, sid):
        if self.direntries[sid] is not None:
            return self.direntries[sid]
        self.directory_fp.seek(sid * 128)
        entry = self.directory_fp.read(128)
        self.direntries[sid] = MaxFileDirEntry(entry, sid, self)
        return self.direntries[sid]

    def _open(self, start, size=UNKNOWN_SIZE, force_FAT=False):
        if size < self.minisectorcutoff and not force_FAT:
            if not self.ministream:
                self.loadminifat()
                size_ministream = self.root.size
                self.ministream = self._open(self.root.isectStart,
                                             size_ministream, force_FAT=True)
            return MaxStream(fp=self.ministream, sect=start, size=size,
                             offset=0, sectorsize=self.minisectorsize,
                             fat=self.minifat, filesize=self.ministream.size)
        else:
            return MaxStream(fp=self.fp, sect=start, size=size,
                             offset=self.sectorsize, sectorsize=self.sectorsize,
                             fat=self.fat, filesize=self._filesize)

    def _find(self, filename):
        if isinstance(filename, str):
            filename = filename.split('/')
        node = self.root
        for name in filename:
            for kid in node.kids:
                if kid.name.lower() == name.lower():
                    break
            node = kid
        return node.sid

    def openstream(self, filename):
        sid = self._find(filename)
        entry = self.direntries[sid]
        return self._open(entry.isectStart, entry.size)


###################
# DATA PROCESSING #
###################

class MaxChunk(object):
    """Representing a chunk of a .max file."""

    __slots__ = "superid", "types", "level", "number", "size", "data"

    def __init__(self, superid, types, level, number, size, data=None):
        self.superid = superid
        self.types = types
        self.data = data
        self.number = 0
        self.level = 0
        self.size = 0
        
    def __str__(self):
        return "%s[%4x]%04X:%s" % ("" * self.level, self.number, self.types, self.data)


class ByteArrayChunk(MaxChunk):
    """A byte array of a .max chunk."""

    def __init__(self, superid, types, level, number, size, data):
        MaxChunk.__init__(self, superid, types, level, number, size, data)
        self.superid = superid
        self.children = []

    def get_first(self, types):
        return None

    def set(self, data, fmt, start, end):
        try:
            self.data = struct.unpack(fmt, data[start:end])
        except Exception as exc:
            self.data = data
            # print('\tStructError: %s' % exc)

    def set_string(self, data):
        try:
            self.data = data.decode('UTF-16LE')
        except:
            self.data = data.decode('UTF-8', 'replace')
        finally:
            self.data = data.decode('UTF-16LE', 'ignore')

    def set_meta_data(self, data):
        metadict = {}
        matkey = False
        try:
            mdatazip = list(zip(*[iter(data.split(b'\x00\x00\x00'))]*2))
            metadata = list(filter(lambda tpl: b'' not in tpl, mdatazip))
            for mdata in metadata:
                header = mdata[0]
                imgkey = header[-1]
                mtitle = b''.join(mdata[1].split(b'\x00')).decode('UTF-8', 'ignore')
                if (len(header) > ROOT_STORE):
                    size = len(header[:-ROOT_STORE])
                    head = struct.unpack('<' + 'IH' * int(size / 6), header[:size])
                    meta = get_longs(header, size, len(header[size:]) // 4)[0]
                    print("  metadata: %s '%s'...%s" % (hex(head[-1]), imgkey, mtitle))
                    metakey = meta[0]
                    metadict[metakey] = [(head[0], head[1])]
                elif metadict and metakey:
                    metadict[metakey].insert(-imgkey, (imgkey, mtitle))
                    print("  imgpath: %s -> '%s: %s'" % (hex(metakey), imgkey, mtitle))
        except:
            self.data = data
            # print('\tStructError: %s' % exc)
        finally:
            self.data = metadict

    def set_data(self, data):
        if (self.types in TYP_NAME):
            self.set_string(data)
        elif (self.types in TYP_LINK):
            self.set(data, '<I', 0, len(data))
        elif (self.types in TYP_VALUE):
            self.set(data, '<f', 0, len(data))
        elif (self.types in TYP_REFS):
            self.set(data, '<' + 'I' * int(len(data) / 4), 0, len(data))
        elif (self.types in TYP_ARRAY):
            self.set(data, '<' + 'f' * int(len(data) / 4), 0, len(data))
        elif (self.types == 0x2510):
            self.set(data, '<' + 'f' * int(len(data) / 4 - 1) + 'I', 0, len(data))
        else:
            self.data = data


class ClassIDChunk(ByteArrayChunk):
    """The class ID subchunk of a .max chunk."""

    def __init__(self, superid, types, level, number, size, data):
        MaxChunk.__init__(self, superid, types, level, number, size, data)
        self.superid = 0x5
        self.dll = None

    def set_data(self, data):
        if (self.types == 0x2042):
            self.set_string(data)  # ClsName
        elif (self.types == 0x2060):
            self.set(data, '<IQI', 0, 16)  # DllIndex, ID, SuperID
        else:
            self.data = ":".join("%02x" % (c) for c in data)


class DirectoryChunk(ByteArrayChunk):
    """The directory chunk of a .max file."""

    def __init__(self, superid, types, level, number, size, data):
        MaxChunk.__init__(self, superid, types, level, number, size, data)
        self.superid = 0x4

    def set_data(self, data):
        if (self.types in (0x2037, 0x2039)):
            self.set_string(data)


class ContainerChunk(MaxChunk):
    """A container chunk in a .max file wich includes byte arrays."""

    def __init__(self, superid, types, level, number, size, data, primReader=ByteArrayChunk):
        MaxChunk.__init__(self, superid, types, level, number, size, data)
        self.primReader = primReader
        self.superid = superid

    def __str__(self):
        return "%s[%4x]%04X" % ("" * self.level, self.number, self.types)

    def get_first(self, types):
        for child in self.children:
            if (child.types == types):
                return child
        return None

    def set_data(self, data):
        reader = ChunkReader()
        self.children = reader.get_chunks(self.superid, data, self.level + 1, ContainerChunk, self.primReader)


class SceneChunk(ContainerChunk):
    """The scene chunk of a .max file wich includes the relevant data for blender."""

    def __init__(self, superid, types, data, number, level, size, primReader=ByteArrayChunk):
        MaxChunk.__init__(self, superid, types, data, number, level, size)
        self.primReader = primReader
        self.superid = 0x2

    def __str__(self):
        return "%s[%4x]%s" % ("" * self.level, self.number, get_cls_name(self))

    def set_data(self, data):
        # print('Scene', "%s %s" % (hex(self.types), self))
        reader = ChunkReader()
        self.children = reader.get_chunks(self.superid, data, self.level + 1, SceneChunk, ByteArrayChunk)


class ChunkReader(object):
    """The chunk reader class for decoding the byte arrays."""

    def __init__(self, name=None):
        self.name = name

    def get_chunks(self, superid, data, level, conReader, primReader):
        chunks = []
        offset = 0
        if (len(data) > ROOT_STORE and level == 0):
            root, step = get_short(data, 0)
            long, step = get_long(data, step)
            print("  reading '%s'..." % self.name, len(data))
            if (root == 0x8B1F):
                long, step = get_long(data, step)
                if (long in (0xB000000, 0xA040000, 0x8000001E)):
                    data = zlib.decompress(data, zlib.MAX_WBITS | 32)
            elif (superid in (0xA, 0xB)):
                chunk = primReader(superid, root, level, 1, len(data), data)
                chunk.set_meta_data(data)
                return [chunk]
        while offset < len(data):
            old = offset
            offset, chunk = self.get_next_chunk(superid, data, offset, level,
                                                len(chunks), conReader, primReader)
            chunks.append(chunk)
        return chunks

    def get_next_chunk(self, superid, data, offset, level, number, conReader, primReader):
        header = 6
        typ, siz = struct.unpack("<Hi", data[offset:offset + header])
        chunksize = siz & UNKNOWN_SIZE
        if (siz == 0):
            siz, = struct.unpack("<q", data[offset + header:offset + header + 8])
            header += 8
            chunksize = siz & MAXFILE_SIZE
        if (siz < 0):
            chunk = conReader(superid, typ, level, number, chunksize, data, primReader)
        else:
            chunk = primReader(superid, typ, level, number, chunksize, data)
        chunkdata = data[offset + header:offset + chunksize]
        chunk.set_data(chunkdata)
        return offset + chunksize, chunk


class Mesh3d(object):
    """Class representing a editable poly mesh object."""
    
    def __init__(self):
        self.verts = []
        self.faces = []
        self.polys = []
        self.cords = []
        self.uvids = []
        self.maps = []
        self.mats = []
        self.points = None
        self.tris = None

    def __str__(self):
        coordsize = [len(crds) // 3 for crds in self.cords]
        return "[%d-%s][%d][%d-%s]" % (len(self.verts) // 3,
                                       '/'.join("%d" % c for c in coordsize),
                                       len(self.polys) // 2, len(self.faces),
                                       '/'.join("%d" % len(u) for u in self.uvids))

    def set(self, indices):
        for point in indices:
            ply = point.points
            key = point.group
            self.mats.append(key)
            self.faces.append(ply)


class Point3d(object):
    """Class representing a three dimensional vector plus pointflag."""

    def __init__(self):
        self.points = None
        self.flags = 0
        self.group = 0
        self.flag1 = 0
        self.flag2 = 0
        self.flag3 = 0
        self.fbits = []

    def __str__(self):
        return "[%s]:'%X'%x,%x,%x[%s]" % ('/'.join("%d" % p for p in self.points),
                                         self.group, self.flag1, self.flag2, self.flag3,
                                         ','.join("%x" % f for f in self.fbits))


class Material(object):
    """Representing a material chunk of a scene chunk."""

    def __init__(self):
        self.data = {}

    def set(self, name, value):
        self.data[name] = value

    def get(self, name, default=None):
        value = None
        if (name in self.data):
            value = self.data[name]
        if (value is None):
            return default
        return value


def get_node(index):
    if isinstance(index, tuple):
        index = index[0]
    global SCENE_LIST
    if (index < len(SCENE_LIST[0].children)):
        return SCENE_LIST[0].children[index]
    return None


def get_node_parent(node):
    parent = None
    if (node):
        chunk = node.get_first(0x0960)
        if (chunk is not None):
            idx, offset = get_long(chunk.data, 0)
            parent = get_node(idx)
    return parent


def get_node_name(node):
    if (node):
        name = node.get_first(0x0962)
        if (name):
            return name.data
    return None


def get_class(chunk):
    global CLS_DIR3_LIST
    if (chunk.types < len(CLS_DIR3_LIST)):
        return CLS_DIR3_LIST[chunk.types]
    return None


def get_dll(chunk):
    global DLL_DIR_LIST
    dll = chunk.get_first(0x2060)
    if (dll):
        idx = dll.data[0]
        if (idx < len(DLL_DIR_LIST)):
            return DLL_DIR_LIST[idx]
    return None


def get_metadata(index):
    global META_DATA
    pathdata = META_DATA[0].data if META_DATA else None
    if pathdata:
        pathname = pathdata.get(index)
        return pathname[0][1] if pathname else None
    return pathdata


def get_guid(chunk):
    clid = get_class(chunk)
    if (clid):
        guid = clid.get_first(0x2060)
        if guid is not None:
            return guid.data[1]
    return chunk.types


def get_super_id(chunk):
    clid = get_class(chunk)
    if (clid):
        suid = clid.get_first(0x2060)
        if suid is not None:
            return suid.data[2]
    return 0x0


def get_cls_name(chunk):
    clid = get_class(chunk)
    if (clid and clid.get_first(0x2042)):
        cls_name = clid.get_first(0x2042).data
        try:
            return "'%s'" % (cls_name)
        except:
            return "'%r'" % (cls_name)
    return u"%04X" % (chunk.types)


def get_references(chunk):
    references = []
    if chunk is None:
        return references
    refs = chunk.get_first(0x2034)
    if (refs):
        references = [get_node(idx) for idx in refs.data]
    return references


def get_reference(chunk):
    references = {}
    refs = chunk.get_first(0x2035)
    if (refs):
        offset = 1
        while offset < len(refs.data):
            key = refs.data[offset]
            offset += 1
            idx = refs.data[offset]
            offset += 1
            references[key] = get_node(idx)
    return references


def read_chunks(maxfile, name, conReader=ContainerChunk, primReader=ByteArrayChunk, superId=None):
    with maxfile.openstream(name) as file:
        scene = file.read()
        reader = ChunkReader(name)
        return reader.get_chunks(superId, scene, 0, conReader, primReader)


def read_class_data(maxfile, filename):
    global CLS_DATA
    CLS_DATA = read_chunks(maxfile, 'ClassData', superId=6)


def read_class_directory(maxfile, filename):
    global CLS_DIR3_LIST
    try:
        CLS_DIR3_LIST = read_chunks(maxfile, 'ClassDirectory3', ContainerChunk, ClassIDChunk)
    except:
        CLS_DIR3_LIST = read_chunks(maxfile, 'ClassDirectory', ContainerChunk, ClassIDChunk)
    for clsdir in CLS_DIR3_LIST:
        clsdir.dll = get_dll(clsdir)


def read_config(maxfile, filename):
    global CONFIG
    CONFIG = read_chunks(maxfile, 'Config', superId=7)


def read_directory(maxfile, filename):
    global DLL_DIR_LIST
    DLL_DIR_LIST = read_chunks(maxfile, 'DllDirectory', ContainerChunk, DirectoryChunk)


def read_video_postqueue(maxfile, filename):
    global VID_PST_QUE
    VID_PST_QUE = read_chunks(maxfile, 'VideoPostQueue', superId=8)


def calc_point(data):
    points = []
    long, offset = get_long(data, 0)
    while (offset < len(data)):
        val, offset = get_long(data, offset)
        flt, offset = get_floats(data, offset, 3)
        points.extend(flt)
    return points


def calc_point_float(data):
    points = []
    long, offset = get_long(data, 0)
    while (offset < len(data)):
        flt, offset = get_floats(data, offset, 3)
        points.extend(flt)
    return points


def calc_point_3d(chunk):
    data = chunk.data
    count, offset = get_long(data, 0)
    pointlist = []
    while (offset < len(data)):
        pt = Point3d()
        long, offset = get_long(data, offset)
        pt.points, offset = get_longs(data, offset, long)
        pt.flags, offset = get_short(data, offset)
        if ((pt.flags & 0x01) != 0):
            (pt.flag1, pt.flag2), offset = get_shorts(data, offset, 2)
        if ((pt.flags & 0x08) != 0):
            pt.group, offset = get_short(data, offset)
        if ((pt.flags & 0x10) != 0):
            pt.flag3, offset = get_long(data, offset)
        if ((pt.flags & 0x20) != 0):
            pt.fbits, offset = get_longs(data, offset, 2 * (long - 3))
        if (len(pt.points) > 0):
            pointlist.append(pt)
    return pointlist


def get_point(floatval, default=0.0):
    uid = get_guid(floatval)
    if (uid == 0x2007):  # Bezier-Float
        flv = floatval.get_first(0x7127)
        if (flv):
            try:
                return flv.get_first(0x2501).data[0]
            except:
                print("SyntaxError: %s - assuming 0.0!\n" % (floatval))
        return default
    if (uid == FLOAT_POINT):  # Float Wire
        flv = get_references(floatval)[0]
        return get_point(flv)
    else:
        return default


def get_point_3d(chunk, default=0.0):
    floats = []
    if (chunk):
        refs = get_references(chunk)
        for fl in refs:
            flt = get_point(fl, default)
            if (fl is not None):
                floats.append(flt)
    return floats


def get_point_array(values):
    verts = []
    if len(values) >= 4:
        count, offset = get_long(values, 0)
        while (count > 0):
            floats, offset = get_floats(values, offset, 3)
            verts.extend(floats)
            count -= 1
    return verts


def get_mesh_polys(data):
    count, offset = get_long(data, 0)
    polygons = []
    while count > 0:
        poly, offset = get_longs(data, offset, 3)
        offset += 8
        polygons.append(poly)
        count -= 1
    return polygons


def get_face_chunks(chunk):
    faceflags = get_long(chunk.data, 0)
    for cnk in chunk.children:
        if (cnk.types == 0x0110):
            size, step = get_long(cnk.data, 0)
            face, step = get_longs(cnk.data, step, size)
    return face


def get_poly_data(chunk):
    offset = 0
    polylist = []
    data = chunk.data
    while (offset < len(data)):
        count, offset = get_long(data, offset)
        points, offset = get_longs(data, offset, count)
        polylist.append(points)
    return polylist


def get_poly_loops(chunk):
    looplist = []
    data = chunk.data
    counts, offset = get_long(data)
    while (offset < len(data)):
        count, offset = get_long(data, offset)
        point, offset = get_longs(data, offset, 2)
        (lp, sp), offset = get_longs(data, offset, 2)
        flags, offset = get_long(data, offset)
        loops = (*point, lp) if sp == FREESECT else point + (lp, sp)
        looplist.append(loops)
    return looplist


def get_uvw_coords(chunk):
    offset = 0
    uvindex = []
    data = chunk.data
    while (offset < len(data)):
        idx, offset = get_long(data, offset)
        uvindex.append(idx)
    cnt = uvindex.pop(0)
    facelist = list(zip(*[iter(uvindex)]*3))
    uvindex.clear()
    return facelist


def get_tri_data(chunk):
    offset = 0
    vindex = []
    data = chunk.data
    head, offset = get_long(data)
    while (offset < head):
        idx, offset = get_long(data, offset)
        vindex.append(idx)
    triangles = list(zip(*[iter(vindex)]*3))
    return triangles


def get_property(properties, idx):
    for child in properties.children:
        if (child.types & 0x100E):
            if (get_short(child.data, 0)[0] == idx):
                return child
    return None


def get_bitmap(chunk):
    if (chunk is not None):
        pathstring = matlib = None
        parameters = get_references(chunk)
        if (len(parameters) >= 2):
            custom = parameters[1].get_first(0x3)
            if (custom is not None):
                pathchunk = custom.get_first(0x1230)
                pathlink = custom.get_first(0x1260)
                if (pathchunk and pathchunk.data):
                    pathstring = pathchunk.data
                elif (pathlink and pathlink.children):
                    matlib = pathlink.children[0]
        if (matlib and matlib.data):
            idsize = len(matlib.data[:-4])
            metaidx = get_longs(matlib.data, idsize, len(matlib.data[idsize:]) // 4)[0]
            pathstring = get_metadata(metaidx[0])
        return pathstring
    return None


def get_color(colors, idx):
    prop = get_property(colors, idx)
    if (prop is not None):
        siz = len(prop.data) - 12
        col, offset = get_floats(prop.data, siz, 3)
        return (col[0], col[1], col[2])
    return None


def get_value(value, idx):
    prop = get_property(value, idx)
    if (prop is not None):
        siz = len(prop.data) - 4
        val, offset = get_float(prop.data, siz)
        return val
    return None


def get_parameter(values, fmt):
    if (fmt == 0x1):
        siz = len(values.data) - 12
        para, offset = get_floats(values.data, siz, 3)
    else:
        siz = len(values.data) - 4
        para, offset = get_float(values.data, siz)
    return para


def get_standard_material(refs):
    material = None
    try:
        if (len(refs) > 2):
            texmap = refs[1]
            colors = refs[2]
            material = Material()
            parameter = get_references(colors)[0]
            bitmap = get_bitmap(get_reference(texmap).get(3))
            shinmap = get_bitmap(get_reference(texmap).get(17))
            transmap = get_bitmap(get_reference(texmap).get(13))
            material.set('ambient', get_color(parameter, 0x00))
            material.set('diffuse', get_color(parameter, 0x01))
            material.set('specular', get_color(parameter, 0x02))
            material.set('shinines', get_value(parameter, 0x0B))
            material.set('emissive', get_color(parameter, 0x08))
            parablock = refs[4]  # ParameterBlock2
            material.set('glossines', get_value(parablock, 0x02))
            material.set('metallic', get_value(parablock, 0x05))
            material.set('refraction', get_value(parablock, 0x06))
            material.set('opacity', get_value(parablock, 0x01))
            if (bitmap is not None):
                material.set('bitmap', Path(bitmap).name)
            if (shinmap is not None):
                material.set('shinmap', Path(shinmap).name)
            if (transmap is not None):
                material.set('transmap', Path(transmap).name)
    except Exception as exc:
        print("\t'StandardMtl' Error:", exc)
    return material


def get_vray_material(vray):
    material = Material()
    try:
        parameter = vray.get(1)
        bitmap = get_bitmap(vray.get(7))
        shinmap = get_bitmap(vray.get(8))
        glossmap = get_bitmap(vray.get(11))
        transmap = get_bitmap(vray.get(19))
        normal = get_references(vray.get(10))
        material.set('diffuse', get_color(parameter, 0x01))
        material.set('specular', get_color(parameter, 0x02))
        material.set('shinines', get_value(parameter, 0x03))
        material.set('emissive', get_color(parameter, 0x33))
        material.set('glossines', get_value(parameter, 0x06))
        material.set('metallic', get_value(parameter, 0x19))
        material.set('refraction', get_value(parameter, 0x09))
        if (bitmap is not None):
            material.set('bitmap', Path(bitmap).name)
        if (shinmap is not None):
            material.set('shinmap', Path(shinmap).name)
        if (glossmap is not None):
            material.set('glossmap', Path(glossmap).name)
        if (transmap is not None):
            material.set('transmap', Path(transmap).name)
        if (normal and len(normal) > 0):
            material.set('strength', get_value(parameter, 0x06))
            refs = get_references(normal[0])
            normalmap = get_bitmap(refs[0])
            if (normalmap is not None):
                material.set('normalmap', Path(normalmap).name)
    except Exception as exc:
        print("\t'VrayMtl' Error:", exc)
    return material


def get_corona_material(mtl):
    material = Material()
    try:
        material = Material()
        corona = mtl[0].children
        parameter = get_reference(mtl[0])
        bitmap = get_bitmap(parameter.get(0))
        shinmap = get_bitmap(parameter.get(1))
        glossmap = get_bitmap(parameter.get(2))
        transmap = get_bitmap(parameter.get(5))
        normal = get_references(parameter.get(6))
        material.set('diffuse', get_parameter(corona[0x03], 1))
        material.set('specular', get_parameter(corona[0x04], 1))
        material.set('shinines', get_parameter(corona[0x3E], 2))
        material.set('emissive', get_parameter(corona[0x08], 1))
        material.set('glossines', get_parameter(corona[0x09], 2))
        material.set('metallic', get_parameter(corona[0x0D], 2))
        material.set('refraction', get_parameter(corona[0x40], 2))
        material.set('opacity', 1.0 - get_parameter(corona[0x0B], 2))
        if (bitmap is not None):
            material.set('bitmap', Path(bitmap).name)
        if (shinmap is not None):
            material.set('shinmap', Path(shinmap).name)
        if (glossmap is not None):
            material.set('glossmap', Path(glossmap).name)
        if (transmap is not None):
            material.set('transmap', Path(transmap).name)
        if (normal and len(normal) > 0):
            values = normal[0].children
            refs = get_references(normal[0])
            normalmap = get_bitmap(refs[0])
            material.set('strength', get_parameter(values[0x03], 2))
            if (normalmap is not None):
                material.set('normalmap', Path(normalmap).name)
    except Exception as exc:
        print("\t'CoronaMtl' Error:", exc)
    return material


def get_arch_material(ad):
    material = Material()
    try:
        material.set('diffuse', get_color(ad, 0x1A))
        material.set('specular', get_color(ad, 0x05))
        material.set('shinines', get_value(ad, 0x0B))
    except:
        pass
    return material


def adjust_material(filename, search, obj, mat):
    dirname = os.path.dirname(filename)
    material = None
    if (mat is not None):
        uid = get_guid(mat)
        if (uid == 0x0002):  # Standard
            mtl_id = mat.get_first(0x4000)
            refs = get_references(mat)
            material = get_standard_material(refs)
        elif (uid == VRAY_MTL):  # VRayMtl
            mtl_id = mat.get_first(0x5431)
            refs = get_reference(mat)
            material = get_vray_material(refs)
        elif (uid == CORO_MTL):  # CoronaMtl
            mtl_id = mat.get_first(0x0FA0)
            refs = get_references(mat)
            material = get_corona_material(refs)
        elif (uid == ARCH_MTL):  # Arch
            refs = get_references(mat)
            material = get_arch_material(refs[0])
        elif (uid == 0x0200):  # Multi/Sub-Object
            refs = get_references(mat)
            for ref in refs:
                if (ref is not None):
                    material = adjust_material(filename, search, obj, ref)
        if (obj is not None) and (material is not None):
            matname = mtl_id.children[0].data if mtl_id else get_cls_name(mat)
            objMaterial = bpy.data.materials.get(matname)
            if objMaterial is None:
                objMaterial = bpy.data.materials.new(matname)
            obj.data.materials.append(objMaterial)
            shader = PrincipledBSDFWrapper(objMaterial, is_readonly=False, use_nodes=True)
            shader.base_color = objMaterial.diffuse_color[:3] = material.get('diffuse', (0.8, 0.8, 0.8))
            shader.specular_tint = objMaterial.specular_color[:3] = material.get('specular', (1, 1, 1))
            shader.specular = objMaterial.specular_intensity = material.get('glossines', 0.5)
            shader.roughness = objMaterial.roughness = 1.0 - material.get('shinines', 0.6)
            shader.alpha = objMaterial.diffuse_color[3] = material.get('opacity', 1.0)
            shader.metallic = objMaterial.metallic = material.get('metallic', 0.0)
            shader.emission_color = material.get('emissive', (0.0, 0.0, 0.0))
            shader.ior = material.get('refraction', 1.45)
            texname = material.get('bitmap', None)
            shinmap = material.get('shinmap', None)
            glossmap = material.get('glossmap', None)
            transmap = material.get('transmap', None)
            normalmap = material.get('normalmap', None)
            if (texname is not None):
                image = load_image(str(texname), dirname, place_holder=False, recursive=search, check_existing=True)
                if (image is not None):
                    shader.base_color_texture.image = image
            if (shinmap is not None):
                image = load_image(str(shinmap), dirname, place_holder=False, recursive=search, check_existing=True)
                if (image is not None):
                    shader.roughness_texture.image = image
            if (glossmap is not None):
                image = load_image(str(glossmap), dirname, place_holder=False, recursive=search, check_existing=True)
                if (image is not None):
                    shader.specular_texture.image = image
            if (normalmap is not None):
                shader.normalmap_strength = material.get('strength', 0.8)
                image = load_image(str(normalmap), dirname, place_holder=False, recursive=search, check_existing=True)
                if (image is not None):
                    shader.normalmap_texture.image = image
            if (transmap is not None):
                if (transmap == texname and shader.node_principled_bsdf.inputs[0].is_linked):
                    imgwrap = shader.base_color_texture.node_image
                    imgwrap.image.alpha_mode = 'CHANNEL_PACKED'
                    shader.material.node_tree.links.new(imgwrap.outputs[1], shader.node_principled_bsdf.inputs[4])
                else:
                    image = load_image(str(transmap), dirname, place_holder=False, recursive=search, check_existing=True)
                    if (image is not None):
                        shader.alpha_texture.image = image
            if (transmap or shader.node_principled_bsdf.inputs[4].default_value < 1.0):
                shader.material.blend_method = 'HASHED'


def get_bezier_floats(pos):
    refs = get_references(pos)
    floats = get_point_3d(pos)
    if any(rf.get_first(0x2501) for rf in refs):
        floats.clear()
        for ref in refs:
            floats.append(ref.get_first(0x2501).data[0])
    return floats


def get_position(pos):
    position = mathutils.Vector()
    if (pos):
        uid = get_guid(pos)
        if (uid == MATRIX_POS):  # Position XYZ
            position = mathutils.Vector(get_bezier_floats(pos))
        elif (uid == 0x2008):  # Bezier Position
            position = mathutils.Vector(pos.get_first(0x2503).data)
        elif (uid == 0x442312):  # TCB Position
            position = mathutils.Vector(pos.get_first(0x2503).data)
        elif (uid == 0x4B4B1002):  # Position List
            refs = get_references(pos)
            if (len(refs) >= 3):
                return get_position(refs[0])
    return position


def get_rotation(pos):
    rotation = mathutils.Quaternion()
    if (pos):
        uid = get_guid(pos)
        if (uid == 0x2012):  # Euler XYZ
            rot = get_bezier_floats(pos)
            rotation = mathutils.Euler((rot[0], rot[1], rot[2])).to_quaternion()
        elif (uid == 0x442313):  # TCB Rotation
            rot = pos.get_first(0x2504).data
            rotation = mathutils.Quaternion((rot[3], rot[2], rot[1], rot[0]))
        elif (uid == MATRIX_ROT):  # Rotation Wire
            return get_rotation(get_references(pos)[0])
        elif (uid == 0x4B4B1003):  # Rotation List
            refs = get_references(pos)
            if (len(refs) > 3):
                return get_rotation(refs[0])
    return rotation


def get_scale(pos):
    scale = mathutils.Vector((1.0, 1.0, 1.0))
    if (pos):
        uid = get_guid(pos)
        if (uid == MATRIX_SCL):  # ScaleXYZ
            pos = get_bezier_floats(pos)
        elif (uid == 0x2010):  # Bezier Scale
            scl = pos.get_first(0x2501)
            if (scl is None):
                scl = pos.get_first(0x2505)
            pos = scl.data
        elif (uid == 0x442315):  # TCB Zoom
            scl = pos.get_first(0x2501)
            if (scl is None):
                scl = pos.get_first(0x2505)
            pos = scl.data
        elif (uid == 0x4B4B1002):  # Scale List
            refs = get_references(pos)
            if (len(refs) >= 3):
                return get_scale(refs[0])
        scale = mathutils.Vector(pos[:3])
    return scale


def create_matrix(prc):
    uid = get_guid(prc)
    mtx = mathutils.Matrix.Identity(4)
    if (uid == 0x2005):  # Position/Rotation/Scale
        pos = get_position(get_references(prc)[0])
        rot = get_rotation(get_references(prc)[1])
        scl = get_scale(get_references(prc)[2])
        mtx = mathutils.Matrix.LocRotScale(pos, rot, scl)
    elif (uid == 0x9154):  # BipSlave Control
        biped = get_references(prc)[-1]
        if biped and (get_guid(biped) == BIPED_ANIM):
            ref = get_references(biped)
            scl = get_scale(get_references(ref[1])[0])
            rot = get_rotation(get_references(ref[2])[0])
            pos = get_position(get_references(ref[3])[0])
            mtx = mathutils.Matrix.LocRotScale(pos, rot, scl)
    return mtx


def get_matrix_mesh_material(node):
    refs = get_reference(node)
    if (refs):
        prs = refs.get(0, None)
        msh = refs.get(1, None)
        mat = refs.get(3, None)
        lyr = refs.get(6, None)
    else:
        refs = get_references(node)
        prs = refs[0]
        msh = refs[1]
        mat = refs[3]
        lyr = refs[6] if len(refs) > 6 else None
    return prs, msh, mat, lyr


def adjust_matrix(obj, node):
    mtx = create_matrix(node)
    obj.matrix_world = mtx @ obj.matrix_world.copy()
    return mtx


def draw_shape(name, mesh, faces):
    data = []
    loopstart = []
    looplines = loop = 0
    nb_faces = len(faces)
    for fid in range(nb_faces):
        polyface = faces[fid]
        looplines += len(polyface)
    shape = bpy.data.meshes.new(name)
    shape.vertices.add(len(mesh.verts) // 3)
    shape.loops.add(looplines)
    shape.polygons.add(nb_faces)
    shape.vertices.foreach_set("co", mesh.verts)
    for vtx in faces:
        loopstart.append(loop)
        data.extend(vtx)
        loop += len(vtx)
    shape.polygons.foreach_set("loop_start", loopstart)
    shape.loops.foreach_set("vertex_index", data)
    return shape


def draw_map(shape, uvcoords, uvwids):
    shape.uv_layers.new(do_init=False)
    coords = [co for i, co in enumerate(uvcoords) if i % 3 in (0, 1)]
    uvcord = list(zip(coords[0::2], coords[1::2]))
    uvloops = tuple(uv for uvws in uvwids for uvid in uvws for uv in uvcord[uvid])
    try:
        shape.uv_layers.active.data.foreach_set("uv", uvloops)
    except Exception as exc:
        print('\tArrayLengthMismatchError: %s' % exc)
    return shape


def create_shape(context, settings, node, mesh, mat):
    filename, obtypes, search = settings
    name = node.get_first(0x0962)
    if name is not None:
        name = name.data
    meshobject = draw_shape(name, mesh, mesh.faces)
    if ('UV' in obtypes and mesh.maps):
        for idx, uvm in enumerate(mesh.maps):
            select = idx if len(mesh.cords[idx]) <= len(mesh.verts) else 0
        meshobject = draw_map(meshobject, mesh.cords[select], mesh.uvids[select])
    meshobject.validate()
    meshobject.update()
    obj = bpy.data.objects.new(name, meshobject)
    context.view_layer.active_layer_collection.collection.objects.link(obj)
    if ('MATERIAL' in obtypes):
        adjust_material(filename, search, obj, mat)
        if (len(mesh.mats) > 0):
            obj.data.polygons.foreach_set("material_index", mesh.mats)
    object_list.append(obj)
    return object_list


def create_dummy_object(context, node, uid):
    dummy = bpy.data.objects.new(get_node_name(node), None)
    dummy.empty_display_type = 'SINGLE_ARROW' if uid == BIPED_OBJ else 'PLAIN_AXES'
    context.view_layer.active_layer_collection.collection.objects.link(dummy)
    return dummy


def create_editable_poly(context, settings, node, msh, mat):
    polychunk = msh.get_first(0x08FE)
    created = []
    if (polychunk):
        mesh = Mesh3d()
        for child in polychunk.children:
            if isinstance(child.data, tuple):
                created = create_shape(context, settings, node, mesh, mat)
            elif (child.types == 0x0100):
                mesh.verts = calc_point(child.data)
            elif (child.types == 0x0108):
                mesh.polys = get_poly_loops(child)
            elif (child.types == 0x010A):
                mesh.tris = calc_point_float(child.data)
            elif (child.types == 0x0118):
                mesh.faces.append(get_face_chunks(child))
            elif (child.types == 0x011A):
                mesh.points = calc_point_3d(child)
            elif (child.types == 0x0124):
                mesh.maps.append(get_long(child.data, 0)[0])
            elif (child.types == 0x0128):
                mesh.cords.append(calc_point_float(child.data))
            elif (child.types == 0x012B):
                mesh.uvids.append(get_poly_data(child))
            elif (child.types == 0x0310):
                mesh.polys = get_poly_data(child)
        if (mesh.points is not None):
            mesh.set(mesh.points)
            created += create_shape(context, settings, node, mesh, mat)
        elif (mesh.faces is not None):
            created += create_shape(context, settings, node, mesh, mat)
        elif (mesh.tris is not None) and 'UV' not in obtypes:
            created += create_shape(context, settings, node, mesh, mat)
    return created


def create_editable_mesh(context, settings, node, msh, mat):
    meshchunk = msh.get_first(0x08FE)
    created = []
    if (meshchunk):
        editmesh = Mesh3d()
        vertex_chunk = meshchunk.get_first(0x0914)
        faceid_chunk = meshchunk.get_first(0x0912)
        if (vertex_chunk and faceid_chunk):
            editmesh.verts = get_point_array(vertex_chunk.data)
            editmesh.faces = get_mesh_polys(faceid_chunk.data)
            for chunk in meshchunk.children:
                if (chunk.types in {0x0924, 0x0959}):
                    editmesh.maps.append(get_long(chunk.data, 0)[0])
                elif (chunk.types in {0x0916, 0x2394}):
                    editmesh.cords.append(get_point_array(chunk.data))
                elif (chunk.types in {0x0918, 0x2396}):
                    editmesh.uvids.append(get_uvw_coords(chunk))
            created += create_shape(context, settings, node, editmesh, mat)
    return created


def create_shell(context, settings, node, shell, mat, mtx):
    refs = get_references(shell)
    created = []
    if refs:
        msh = refs[-1]
        created, uid = create_mesh(context, settings, node, msh, mat, mtx)
    return created


def create_plane(context, node, plane, mat, mtx):
    created = []
    name = node.get_first(0x0962)
    if name is not None:
        name = name.data
    parablock = get_references(plane)[0]
    try:
        length = get_float(parablock.children[1].data, 15)[0]
        width = get_float(parablock.children[2].data, 15)[0]
    except:
        length = UNPACK_BOX_DATA(parablock.children[1].data)[6]
        width = UNPACK_BOX_DATA(parablock.children[2].data)[6]
    bpy.ops.mesh.primitive_plane_add(size=1.0, scale=(width, length, 0.0))
    obj = context.selected_objects[0]
    if name is not None:
        obj.name = str(name)
    adjust_matrix(obj, mtx)
    plane.geometry = obj
    created.append(obj)
    return created


def create_box(context, node, box, mat, mtx):
    created = []
    name = node.get_first(0x0962)
    if name is not None:
        name = name.data
    parablock = get_references(box)[0]
    try:
        length = get_float(parablock.children[1].data, 15)[0]
        width = get_float(parablock.children[2].data, 15)[0]
        depth = get_float(parablock.children[3].data, 15)[0]
    except:
        length = UNPACK_BOX_DATA(parablock.children[1].data)[6]
        width  = UNPACK_BOX_DATA(parablock.children[2].data)[6]
        depth = UNPACK_BOX_DATA(parablock.children[3].data)[6]
    height = -depth if (depth < 0) else depth
    bpy.ops.mesh.primitive_cube_add(size=1.0, scale=(width, length, height))
    obj = context.selected_objects[0]
    if name is not None:
        obj.name = name
    adjust_matrix(obj, mtx)
    box.geometry = obj
    created.append(obj)
    return created


def create_sphere(context, node, sphere, mat, mtx):
    created = []
    name = node.get_first(0x0962)
    if name is not None:
        name = name.data
    parablock = get_references(sphere)[0]
    try:
        rd = get_float(parablock.children[1].data, 15)[0]
    except:
        rd = UNPACK_BOX_DATA(parablock.children[1].data)[6]
    bpy.ops.mesh.primitive_uv_sphere_add(radius=rd)
    obj = context.selected_objects[0]
    if name is not None:
        obj.name = name
    adjust_matrix(obj, mtx)
    sphere.geometry = obj
    created.append(obj)
    return created


def create_torus(context, node, torus, mat, mtx):
    created = []
    name = node.get_first(0x0962)
    if name is not None:
        name = name.data
    parablock = get_references(torus)[0]
    try:
        rd1 = get_float(parablock.children[1].data, 15)[0]
        rd2 = get_float(parablock.children[2].data, 15)[0]
    except:
        rd1 = UNPACK_BOX_DATA(parablock.children[1].data)[6]
        rd2 = UNPACK_BOX_DATA(parablock.children[2].data)[6]
    bpy.ops.mesh.primitive_torus_add(major_radius=rd1, minor_radius=rd2)
    obj = context.selected_objects[0]
    if name is not None:
        obj.name = str(name)
    adjust_matrix(obj, mtx)
    torus.geometry = obj
    created.append(obj)
    return created


def create_cylinder(context, node, cylinder, mat, mtx):
    created = []
    name = node.get_first(0x0962)
    if name is not None:
        name = name.data
    parablock = get_references(cylinder)[0]
    try:
        rd = get_float(parablock.children[1].data, 15)[0]
        hg = get_float(parablock.children[2].data, 15)[0]
    except:
        rd = UNPACK_BOX_DATA(parablock.children[1].data)[6]
        hg = UNPACK_BOX_DATA(parablock.children[2].data)[6]
    rad = -rd if (rd < 0) else rd
    height = -hg if (hg < 0) else hg
    bpy.ops.mesh.primitive_cylinder_add(radius=rad, depth=height)
    obj = context.selected_objects[0]
    if name is not None:
        obj.name = name
    adjust_matrix(obj, mtx)
    cylinder.geometry = obj
    created.append(obj)
    return created


def create_cone(context, node, cone, mat, mtx):
    created = []
    name = node.get_first(0x0962)
    if name is not None:
        name = name.data
    parablock = get_references(cone)[0]
    try:
        rd1 = get_float(parablock.children[1].data, 15)[0]
        rd2 = get_float(parablock.children[2].data, 15)[0]
        hgt = get_float(parablock.children[3].data, 15)[0]
    except:
        rd1 = UNPACK_BOX_DATA(parablock.children[1].data)[6]
        rd2 = UNPACK_BOX_DATA(parablock.children[2].data)[6]
        hgt = UNPACK_BOX_DATA(parablock.children[3].data)[6]
    height = -hgt if (hgt < 0) else hgt
    bpy.ops.mesh.primitive_cone_add(radius1=rd1, radius2=rd2, depth=height)
    obj = context.selected_objects[0]
    if name is not None:
        obj.name = str(name)
    adjust_matrix(obj, mtx)
    cone.geometry = obj
    created.append(obj)
    return created


def create_skipable(context, node, skip):
    name = node.get_first(0x0962)
    if name is not None:
        name = name.data
        print("    skipping %s '%s'... " % (skip, name))
    return []


def create_mesh(context, settings, node, msh, mat, mtx):
    created = []
    object_list.clear()
    uid = get_guid(msh)
    if (uid in {POLY_MESH, EDIT_POLY}):
        created = create_editable_poly(context, settings, node, msh, mat)
    elif (uid in {0x019, EDIT_MESH}):
        created = create_editable_mesh(context, settings, node, msh, mat)
    elif (uid == 0x010 and 'PRIMITIVE' in settings[1]):
        created = create_box(context, node, msh, mat, mtx)
    elif (uid == 0x011 and 'PRIMITIVE' in settings[1]):
        created = create_sphere(context, node, msh, mat, mtx)
    elif (uid == 0x012 and 'PRIMITIVE' in settings[1]):
        created = create_cylinder(context, node, msh, mat, mtx)
    elif (uid == 0x020 and 'PRIMITIVE' in settings[1]):
        created = create_torus(context, node, msh, mat, mtx)
    elif (uid == CONE and 'PRIMITIVE' in settings[1]):
        created = create_cone(context, node, msh, mat, mtx)
    elif (uid == PLANE and 'PRIMITIVE' in settings[1]):
        created = create_plane(context, node, msh, mat, mtx)
    elif (uid in {0x2032, 0x2033}):
        created = create_shell(context, settings, node, msh, mat, mtx)
    elif (uid == DUMMY and 'EMPTY' in settings[1]):
        created = [create_dummy_object(context, node, uid)]
    elif (uid == BIPED_OBJ and 'ARMATURE' in settings[1]):
        created = [create_dummy_object(context, node, uid)]
    else:
        skip = SKIPPABLE.get(uid)
        if (skip is not None):
            created = create_skipable(context, node, skip)
    return created, uid


def create_object(context, settings, node, transform):
    parent = get_node_parent(node)
    nodename = get_node_name(node)
    parentname = get_node_name(parent)
    prs, msh, mat, lyr = get_matrix_mesh_material(node)
    created, uid = create_mesh(context, settings, node, msh, mat, prs)
    created = [idx for ob, idx in enumerate(created) if idx not in created[:ob]]
    for obj in created:
        if obj.name != nodename:
            parent_dict[obj.name] = parentname
        if (transform and obj.type == 'MESH'):
            nodeloca = node.get_first(0x96A)
            noderota = node.get_first(0x96B)
            nodesize = node.get_first(0x96C)
            quats = noderota.data if noderota else (0.0, 0.0, 0.0, 1.0)
            pivot = mathutils.Vector(nodeloca.data if nodeloca else (0.0, 0.0, 0.0))
            angle = mathutils.Quaternion((quats[3], quats[2], quats[1], quats[0]))
            scale = mathutils.Vector(nodesize.data[:3] if nodesize else (1.0, 1.0, 1.0))
            p_mtx = mathutils.Matrix.LocRotScale(pivot, angle, scale)
            obj.data.transform(p_mtx)
    matrix_dict[nodename] = create_matrix(prs)
    parent_dict[nodename] = parentname
    return nodename, created


def make_scene(context, settings, mscale, transform, parent):
    imported = []
    for chunk in parent.children:
        if isinstance(chunk, SceneChunk) and get_guid(chunk) in {0x1, 0x14} and get_super_id(chunk) <= 0x1:
            try:
                imported.append(create_object(context, settings, chunk, transform))
            except Exception as exc:
                print("\tImportError: %s %s" % (exc, chunk), get_node_name(chunk))

    # Apply matrix and assign parents to objects
    objects = dict(imported)
    for idx, objs in objects.items():
        pt_name = parent_dict.get(idx)
        parents = objects.get(pt_name)
        obj_mtx = matrix_dict.get(idx, mathutils.Matrix())
        prt_mtx = matrix_dict.get(pt_name, mathutils.Matrix())
        for obj in objs:
            if parents:
                try:
                    obj.parent = parents[0]
                except TypeError as te:
                    print("\tTypeError: %s '%s'" % (te, pt_name))
            if obj_mtx:
                if obj.parent and obj.parent.empty_display_type != 'SINGLE_ARROW':
                    trans_mtx = obj.parent.matrix_world @ obj_mtx
                else:
                    trans_mtx = prt_mtx @ obj_mtx
                if transform:
                    obj.matrix_world = trans_mtx
                obj.matrix_world = mscale @ obj.matrix_world


def read_scene(context, maxfile, settings, mscale, transform):
    global SCENE_LIST, META_DATA
    metasid = max(entry.sid for entry in maxfile.direntries if entry is not None)
    SCENE_LIST = read_chunks(maxfile, 'Scene', SceneChunk)
    META_DATA = read_chunks(maxfile, maxfile.direntries[metasid].name, superId=metasid) if metasid >= 0xA else []
    make_scene(context, settings, mscale, transform, SCENE_LIST[0])
    # print('Directory', maxfile.direntries[0].kids_dict.keys())


def read(context, filename, mscale, obtypes, search, transform):
    if (is_maxfile(filename)):
        settings = filename, obtypes, search
        maxfile = ImportMaxFile(filename)
        read_class_data(maxfile, filename)
        read_config(maxfile, filename)
        read_directory(maxfile, filename)
        read_class_directory(maxfile, filename)
        read_video_postqueue(maxfile, filename)
        read_scene(context, maxfile, settings, mscale, transform)
    else:
        print("File seems to be no 3D Studio Max file!")


def load(operator, context, files=[], directory="", filepath="", scale_objects=1.0, use_collection=False,
         use_image_search=True, object_filter=None, use_apply_matrix=True, global_matrix=None):

    object_dict.clear()
    parent_dict.clear()
    matrix_dict.clear()

    context.window.cursor_set('WAIT')
    mscale = mathutils.Matrix.Scale(scale_objects, 4)
    if global_matrix is not None:
        mscale = global_matrix @ mscale

    if not len(files):
        files = [Path(filepath)]
        directory = Path(filepath).parent

    if not object_filter:
        object_filter = {'MATERIAL', 'UV', 'PRIMITIVE', 'EMPTY'}

    default_layer = context.view_layer.active_layer_collection.collection
    for fl in files:
        if use_collection:
            collection = bpy.data.collections.new(Path(fl.name).stem)
            context.scene.collection.children.link(collection)
            context.view_layer.active_layer_collection = context.view_layer.layer_collection.children[collection.name]
        read(context, os.path.join(directory, fl.name), mscale, obtypes=object_filter, search=use_image_search, transform=use_apply_matrix)

    object_dict.clear()
    parent_dict.clear()
    matrix_dict.clear()

    active = context.view_layer.layer_collection.children.get(default_layer.name)
    if active is not None:
        context.view_layer.active_layer_collection = active

    context.window.cursor_set('DEFAULT')

    return {'FINISHED'}

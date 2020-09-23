
# -*- coding: UTF-8 -*-
import struct

filepath = 'C:\Program Files (x86)\Steam\steam.exe'
pe_info = {}


def unpack(val):
    if len(val) == 2:
        return struct.unpack('<H', val)[0]
    if len(val) == 4:
        return struct.unpack('<I', val)[0]
    if len(val) == 8:
        return struct.unpack('<Q', val)[0]


dos_header_struct = [
    {'name': 'e_magic', 'magic': b'MZ'},
    {'name': 'e_cblp'},
    {'name': 'e_cp'},
    {'name': 'e_crlc'},
    {'name': 'e_cparhdr'},
    {'name': 'e_minalloc'},
    {'name': 'e_maxalloc'},
    {'name': 'e_ss'},
    {'name': 'e_sp'},
    {'name': 'e_csum'},
    {'name': 'e_ip'},
    {'name': 'e_cs'},
    {'name': 'e_lfarlc'},
    {'name': 'e_ovno'},
    {'name': 'e_res', 'count': 4},
    {'name': 'e_oemid'},
    {'name': 'e_oeminfo'},
    {'name': 'e_res2', 'count': 10},
    {'name': 'e_lfanew', 'size': 4},
]

IMAGE_DATA_DIRECTORY = [
    {'name': 'VirtualAddress', 'size': 4},
    {'name': 'Size', 'size': 4},
]

optional_headerXX_struct = [
    {'name': 'Magic'},
    {'name': 'MajorLinkerVersion', 'size': 1},
    {'name': 'MinorLinkerVersion', 'size': 1},
    {'name': 'SizeOfCode', 'size': 4},
    {'name': 'SizeOfInitializedData', 'size': 4},
    {'name': 'SizeOfUnInitializedData', 'size': 4},
    {'name': 'AddressOfEntryPoint', 'size': 4},
    {'name': 'BaseOfCode', 'size': 4},
    {'name': 'BaseOfData', 'size': 4,
        'hide': lambda: True if pe_info['IMAGE_NT_HEADERS']['FileHeader']['SizeOfOptionalHeader'] == b'\xf0\x00' else False},
    {'name': 'ImageBase',
        'size': lambda: 8 if pe_info['IMAGE_NT_HEADERS']['FileHeader']['SizeOfOptionalHeader'] == b'\xf0\x00' else 4},
    {'name': 'SectionAlignment', 'size': 4},
    {'name': 'FileAlignment', 'size': 4},
    {'name': 'MajorOperatingSystemVersion'},
    {'name': 'MinorOperatingsystemversion'},
    {'name': 'MajorImageVersion'},
    {'name': 'MinorImageVersion'},
    {'name': 'MajorSubsybtemVersion'},
    {'name': 'MinorSubsybtemVersion'},
    {'name': 'Win32VersionValue', 'size': 4},
    {'name': 'SizeOfImage', 'size': 4},
    {'name': 'SizeoOfHeaders', 'size': 4},
    {'name': 'CheckSum', 'size': 4},
    {'name': 'Subsystem'},
    {'name': 'DllCharacteristics'},
    {'name': 'SizeOfStackReserve',
        'size': lambda: 8 if pe_info['IMAGE_NT_HEADERS']['FileHeader']['SizeOfOptionalHeader'] == b'\xf0\x00' else 4},
    {'name': 'SizeOfStackCommit',
        'size': lambda: 8 if pe_info['IMAGE_NT_HEADERS']['FileHeader']['SizeOfOptionalHeader'] == b'\xf0\x00' else 4},
    {'name': 'SizeOfHeapReserve',
        'size': lambda: 8 if pe_info['IMAGE_NT_HEADERS']['FileHeader']['SizeOfOptionalHeader'] == b'\xf0\x00' else 4},
    {'name': 'SizeOfHeapCommit',
        'size': lambda: 8 if pe_info['IMAGE_NT_HEADERS']['FileHeader']['SizeOfOptionalHeader'] == b'\xf0\x00' else 4},
    {'name': 'LoaderFlages', 'size': 4},
    {'name': 'NumberOfRvaAndSizes', 'size': 4},
    {'name': 'DataDirectory', 'count': 16, 'nest': IMAGE_DATA_DIRECTORY},
]

section_header_struct = [
    {'name': 'Name', 'size': 8},
    {'name': 'Misc', 'size': 4},
    {'name': 'VirtualAddress', 'size': 4},
    {'name': 'SizeOfRawData', 'size': 4},
    {'name': 'PointerToRawData', 'size': 4},
    {'name': 'PointerToRelocations', 'size': 4},
    {'name': 'PointerToLinenumbers', 'size': 4},
    {'name': 'NumberOfRelocations'},
    {'name': 'NumberOfLinenumbers'},
    {'name': 'Characteristics', 'size': 4},
]

file_header_struct = [
    {'name': 'Machine'},
    {'name': 'NumberOfSections'},
    {'name': 'TimeDateStamp', 'size': 4},
    {'name': 'PointerToSymbols', 'size': 4},
    {'name': 'NumberOfSymbols', 'size': 4},
    {'name': 'SizeOfOptionalHeader'},
    {'name': 'Characteristics'},
]


nt_header_struct = [
    {'name': 'Signature', 'size': 4, 'magic': b'PE\x00\x00'},
    {'name': 'FileHeader', 'nest': file_header_struct},
    {'name': 'OptionalHeader', 'nest': optional_headerXX_struct},
]

def endf():
    # if(pe_info['Imports'][-1]['int'][-1]['IMAGE_IMPORT_BY_NAME']['Name'][-1] == b'\x00'):
    #     print(pe_info['Imports'][-1]['int'][-1]['IMAGE_IMPORT_BY_NAME']['Name'])
    return  pe_info['Imports'][-1]['int'][-1]['IMAGE_IMPORT_BY_NAME']['Name'][-1] == b'\x00'

IMAGE_IMPORT_BY_NAME  = [
    {'name': 'Hint'},
    {'name': 'Name','size':1,'count':0,'end':lambda: 
        endf()},
]

IMAGE_THUNK_DATA = [
    {'name': 'ForwarderString',
        'size': lambda: 8 if pe_info['IMAGE_NT_HEADERS']['FileHeader']['SizeOfOptionalHeader'] == b'\xf0\x00' else 4
    },
    {'name': 
        'IMAGE_IMPORT_BY_NAME',
        'slient':True,
        'stop':lambda:  
            pe_info['Imports'][-1]['int'][-1]['ForwarderString'][-1]&(1<<7) == 1,
        'nest':IMAGE_IMPORT_BY_NAME,
        'offset':lambda: offset(unpack(pe_info['Imports'][-1]['int'][-1]['ForwarderString']))
    },
]


def int_end():
    NULL = b'\x00\x00\x00\x00\x00\x00\x00\x00' if pe_info['IMAGE_NT_HEADERS'][
        'FileHeader']['SizeOfOptionalHeader'] == b'\xf0\x00' else b'\x00\x00\x00\x00'
    last_int = pe_info['Imports'][-1]['int'][-1]
    return last_int['ForwarderString'] == NULL

def iat_end():
    NULL = b'\x00\x00\x00\x00\x00\x00\x00\x00' if pe_info['IMAGE_NT_HEADERS'][
        'FileHeader']['SizeOfOptionalHeader'] == b'\xf0\x00' else b'\x00\x00\x00\x00'
    last_iat = pe_info['Imports'][-1]['iat'][-1]
    return last_iat['ForwarderString'] == NULL

def offset(rva):
    for p in pe_info['IMAGE_SECTION_HEADER']:
        section_rva_start = unpack(p['VirtualAddress'])
        section_size = unpack(p['Misc'])
        if rva > section_rva_start and rva < section_rva_start+section_size:
            section_offset = unpack(p['PointerToRawData'])
            return section_offset+rva-section_rva_start


IMAGE_IMPORT_DESCRIPTOR = [
    {'name': 'OriginalFirstThunk', 'size': 4},
    {'name': 'TimeDateStamp', 'size': 4},
    {'name': 'ForwarderChain', 'size': 4},
    {'name': 'Name', 'size': 4, 'type': 'string'},
    {'name': 'FirstThunk', 'size': 4},
    {'name': 'int', 'slient': True,
        'nest': IMAGE_THUNK_DATA,
        # 'stop': lambda: len(pe_info['Imports']) > 0
        #     and pe_info['Imports'][-1]['OriginalFirstThunk'] == b'\x00\x00\x00\x00'
        #     and pe_info['Imports'][-1]['TimeDateStamp'] == b'\x00\x00\x00\x00'
        #     and pe_info['Imports'][-1]['ForwarderChain'] == b'\x00\x00\x00\x00'
        #     and pe_info['Imports'][-1]['Name'] == b'\x00\x00\x00\x00'
        #     and pe_info['Imports'][-1]['FirstThunk'] == b'\x00\x00\x00\x00',
        'end': lambda: int_end(), 'count':0,
        'offset':lambda:offset(unpack(pe_info['Imports'][-1]['OriginalFirstThunk']))
     },
    #  {'name': 'iat', 'slient': True,
    #     'nest': IMAGE_THUNK_DATA,
    #     # 'stop': lambda: len(pe_info['Imports']) > 0
    #     #     and pe_info['Imports'][-1]['OriginalFirstThunk'] == b'\x00\x00\x00\x00'
    #     #     and pe_info['Imports'][-1]['TimeDateStamp'] == b'\x00\x00\x00\x00'
    #     #     and pe_info['Imports'][-1]['ForwarderChain'] == b'\x00\x00\x00\x00'
    #     #     and pe_info['Imports'][-1]['Name'] == b'\x00\x00\x00\x00'
    #     #     and pe_info['Imports'][-1]['FirstThunk'] == b'\x00\x00\x00\x00',
    #     'end': lambda: iat_end(), 'count':0,
    #     'offset':lambda:offset(unpack(pe_info['Imports'][-1]['OriginalFirstThunk']))
    #  }
    #  ,
]


def getImportTableOffest():
    imp_dir = pe_info['IMAGE_NT_HEADERS']['OptionalHeader']['DataDirectory'][1]
    imp_rva_start = unpack(imp_dir['VirtualAddress'])
    imp_size = unpack( imp_dir['Size'])
    imp_offset_start = offset(imp_rva_start)
    return imp_offset_start

def end_imports():
    return pe_info['Imports'][-1]['OriginalFirstThunk'] == b'\x00\x00\x00\x00'and pe_info['Imports'][-1]['TimeDateStamp'] == b'\x00\x00\x00\x00' and pe_info['Imports'][-1]['ForwarderChain'] == b'\x00\x00\x00\x00' and pe_info['Imports'][-1]['Name'] == b'\x00\x00\x00\x00' and pe_info['Imports'][-1]['FirstThunk'] == b'\x00\x00\x00\x00'

pe_struct = [
    {'name': 'IMAGE_DOS_HEADER', 'nest': dos_header_struct},
    {'name': 'IMAGE_NT_HEADERS', 'nest': nt_header_struct, 'offset': lambda: unpack(
         pe_info['IMAGE_DOS_HEADER']['e_lfanew'])},
    {'name': 'IMAGE_SECTION_HEADER', 'nest': section_header_struct, 'count': lambda: unpack(
         pe_info['IMAGE_NT_HEADERS']['FileHeader']['NumberOfSections'])},
    {
        'name': 'Imports', 'nest': IMAGE_IMPORT_DESCRIPTOR, 'count': 0,
        'offset': lambda: getImportTableOffest(),
        'end': lambda: end_imports()    
     },
]


def V(kv, k):
    if callable(kv[k]):
        return kv[k]()
    return kv[k]


def parseStruct(f, header_struct, header, base_pos=None):
    if base_pos is not None:
        f.seek(base_pos)
    for p in header_struct:
        if 'hide' in p and V(p, 'hide'):
            continue
        if 'stop' in p and V(p, 'stop'):
            continue
        old_seek = f.tell()
        name = V(p, 'name')
        count = 1 if 'count' not in p else V(p, 'count')
        if 'nest' in p:
            if count == 1:
                sub_pos = None
                if 'offset' in p:
                    sub_pos = V(p, 'offset')
                sub_header = {}
                header[name] = sub_header
                parseStruct(f, V(p, 'nest'), sub_header, sub_pos)
            elif count == 0:
                header[name] = []
                if 'offset' in p:
                    o = V(p, 'offset')
                    if o is None:
                       continue
                    f.seek(o)
                while True:
                    sub_header = {}
                    header[name].append(sub_header)
                    parseStruct(f, V(p, 'nest'), sub_header)
                    if V(p, 'end'):
                        header[name].pop()
                        break
            else:
                header[name] = []
                for i in range(count):
                    sub_header = {}
                    header[name].append(sub_header)
                    parseStruct(f, V(p, 'nest'), sub_header)
        else:
            size = 2 if 'size' not in p else V(p, 'size')
            if count == 1:
                h = f.read(size)
                if 'magic' in p and V(p, 'magic') != h:
                    raise ValueError('%s的值%s不符合%s' % (name, h, V(p, 'magic')))
                if 'type' in p and V(p, 'type') == 'string':
                    print(readText(offset(unpack(h))))
                header[name] = h

            elif count == 0:
                header[name] = []   
                if 'offset' in p:
                    f.seek(V(p, 'offset'))
                while True:
                    c = f.read(size)
                    header[name].append(c)
                    if V(p, 'end'):
                        header[name].pop()
                        break
            else:
                header[name] = []
                for i in range(count):
                     header[name].append(f.read(size))
            
        if 'slient' in p and p['slient']:
            f.seek(old_seek)


def readText(address):
    old_seek = f.tell()
    if address is None:
        return None
    f.seek(address)
    res = b''
    while True:
        c = f.read(1)
        if c == b'\x00':
            break
        res += c
    f.seek(old_seek)
    return str(res, 'utf-8')


def parseImports():
    for p in pe_info['Imports'][:-1]:
        name_str_off = offset(unpack( p['Name']))
        name_text = readText(name_str_off)
        print(name_text)
        int_data = {}
        int_off = offset(unpack( p['OriginalFirstThunk']))
        # parseStruct(f,INT,int_data,int_off)
        # print(int_data)


def parse(f):
    global pe_info
    parseStruct(f, pe_struct, pe_info)
    # print(pe_info)
    # print(pe_info['IMAGE_NT_HEADERS']['FileHeader']['NumberOfSections'])arnold

    # print(pe_info['IMAGE_NT_HEADERS']['OptionalHeader']['AddressOfEntryPoint'])
    # print(pe_info['IMAGE_NT_HEADERS']['OptionalHeader']['BaseOfCode'])
    # print(pe_info['IMAGE_NT_HEADERS']['OptionalHeader']['DataDirectory'])
    # for p in (pe_info['IMAGE_NT_HEADERS']['OptionalHeader']['DataDirectory']):
    #     print("%s %s" % (hex(struct.unpack('<I', p['VirtualAddress'])[
    #           0]), hex(struct.unpack('<I', p['Size'])[0])))
    # print('---------------------')
    # for p in (pe_info['IMAGE_SECTION_HEADER']):
    #     print("%s %s %s %s" % (p['Name'], hex(struct.unpack('<I', p['VirtualAddress'])[0]), hex(
    #         struct.unpack('<I', p['Misc'])[0]), hex(struct.unpack('<I', p['PointerToRawData'])[0])))
    # print('-----------')
    # parseImports()
    for i in pe_info['Imports'][1]['int']:
        if unpack(i['ForwarderString']) == 0:
            continue
        ss=b''
        for s in i['IMAGE_IMPORT_BY_NAME']['Name']:
            ss+=s
        print(str(ss))


with open(filepath, 'rb') as f:
    parse(f)

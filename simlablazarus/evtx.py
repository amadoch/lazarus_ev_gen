#Generador de Evtx
import hashlib
import logging

from simlablazarus import artifact

module_logger = logging.getLogger("lab_lazarus.evtx")

import logging
import re
import time
import uuid
import zlib
from datetime import datetime
from pathlib import Path
from struct import pack

try:
    from lxml import etree
    has_lxml = True
except ImportError:
    has_lxml = False

# EVTX file signature: "ElfFile\x00"
EVTX_HEADER_SIGNATURE = 0x456C6646696C6500

# EVTX file signature: "ElfChnk\x00"
EVTX_CHUNK_HEADER_SIGNATURE = 0x456C6643686E6B00

# Recode header signature: "\x2a\x2a\x00\x00"
EVTX_EVENT_RECORD_HEADER_SIGNATURE = 0x2a2a0000

# Fragment header in BinXML
FLAGMENT_HEADER = 0x0f010100

# 3.1: Seen on Windows Vista and later
# 3.2: Seen on Windows 10 (2004) and later
EVTX_MAJOR_VERSION = 0x0003
EVTX_MINOR_VERSION = 0x0002

# Chnk size must be 0x10000
MAX_CHUNK_SIZE = 0x10000

HEADER_SIZE = 128

HEADER_BLOCK_SIZE = 4096

# starting value of the event record identifier
START_EVENT_RECORD_ID = 1

TOKEN_TYPE = {
    "BinXmlTokenEOF": 0x00,
    "BinXmlTokenOpenStartElementTag_noAttribute": 0x01,
    "BinXmlTokenCloseStartElementTag": 0x02,
    "BinXmlTokenCloseEmptyElementTag": 0x03,
    "BinXmlTokenEndElementTag": 0x04,
    "BinXmlTokenValue": 0x05,
    "BinXmlTokenAttribute": 0x06,
    "BinXmlTokenCDATASection": 0x07,
    "BinXmlTokenCharRef": 0x08,
    "BinXmlTokenEntityRef": 0x09,
    "BinXmlTokenPITarget": 0x0a,
    "BinXmlTokenPIData": 0x0b,
    "BinXmlTokenTemplateInstance": 0x0c,
    "BinXmlTokenNormalSubstitution": 0x0d,
    "BinXmlTokenOptionalSubstitution": 0x0e,
    "BinXmlFragmentHeaderToken": 0x0f,
    "BinXmlTokenOpenStartElementTag_Attribute": 0x41,
    "BinXmlTokenValue_Next": 0x45,
    "BinXmlTokenAttribute_Next": 0x46,
}

VALUE_TYPE = {
    "NullType": 0x00,
    "StringType": 0x01,
    "AnsiStringType": 0x02,
    "Int8Type": 0x03,
    "UInt8Type": 0x04,
    "Int16Type": 0x05,
    "UInt16Type": 0x06,
    "Int32Type": 0x07,
    "UInt32Type": 0x08,
    "Int64Type": 0x09,
    "UInt64Type": 0x0a,
    "Real32Type": 0x0b,
    "Real64Type": 0x0c,
    "BoolType": 0x0d,
    "BinaryType": 0x0e,
    "GuidType": 0x0f,
    "SizeTType": 0x10,
    "FileTimeType": 0x11,
    "SysTimeType": 0x12,
    "SidType": 0x13,
    "HexInt32Type": 0x14,
    "HexInt64Type": 0x15,
    "EvtHandle": 0x20,
    "BinXmlType": 0x21,
    "EvtXml": 0x22,
}

EVTX_HEADER = {
    "signature": (">Q", EVTX_HEADER_SIGNATURE),
    "first_chunk_number": ("Q", 0),
    "last_chunk_number": ("Q", None),
    "next_record_identifier": ("Q", None),
    "header_size": ("I", HEADER_SIZE),
    "minor_version": ("H", EVTX_MINOR_VERSION),
    "major_version": ("H", EVTX_MAJOR_VERSION),
    "header_block_size": ("H", HEADER_BLOCK_SIZE),
    "number_of_chunks": ("H", None),
    "unknown1": ("76s", b'\00' * 76),
    "file_flags": ("I", 0x0001),
    "checksum": ("I", None), # Contains a CRC32 of bytes 0 to 120
    "unknown2": ("3968s", b'\00' * 3968),
}

EVTX_CHUNK_HEADER = {
    "signature": (">Q", EVTX_CHUNK_HEADER_SIGNATURE),
    "first_event_record_number": ("Q", 0x01),
    "last_event_record_number": ("Q", None),
    "first_event_record_identifier": ("Q", START_EVENT_RECORD_ID),
    "last_event_record_identifier": ("Q", None),
    "header_size": ("I", HEADER_SIZE),
    "last_event_record_offset": ("I", 0), # Start offset of the last record header (0x2a2a0000) from offset 0x1000. max chunk size == 65536 or 0x10000
    "free_space_offset": ("I", None),
    "event_records_checksum": ("I", None), # Contains a CRC32 of the events records data
    "unknown1": ("64s", b'\00' * 64),
    "unknown2": ("I", 0x01),
    "checksum": ("I", None), # Contains a CRC32 of bytes 0 to 120 (not 124) and 128 to 512
}

EVTX_EVENT_RECORD_HEADER = {
    "signature": (">I", EVTX_EVENT_RECORD_HEADER_SIGNATURE),
    "size": ("I", None),
    "identifier": ("Q", None), # same first_event_record_identifier
    "written_time": ("Q", None),
}

# only use template
BINXML_TEMPLATE_DEFINITION = {
    "unknown1": ("B", 0x01),
    "template_identifier_4": ("4s", None), # template_identifier[4:]
    "template_definition_data_offset": ("I", 0x77777777),
    "next_template_offset": ("I", 0),
    "template_identifier": ("16s", None),
    "data_size": ("I", None)
}

BINXML_ELEMENT_START = {
    "open_start_element_tag_token": ("B", None),
    #"dependency_identifier": ("H", 0xffff), # only use template definition
    "data_size": ("I", None), # Size after Element start
    "element_name_offset": ("I", 0x99999999), # Offset of Element name following Element start from 0x1000
}

BINXML_NAME = {
    "unknown": ("I", 0),
    "name_hash": ("H", None),
    "number_of_characters": ("H", None),
}

BINXML_ATTRIBUTE = {
    "attribute_token": ("B", None),
    "attribute_name_offset": ("I", 0x88888888),
}

BINXML_VALUE_TEXT = {
    "value_token": ("B", TOKEN_TYPE["BinXmlTokenValue"]),
    "value_type": ("B", VALUE_TYPE["StringType"]),
    "data_size": ("H", None),
}

def to_wordpack(str_name):
    data = b""
    for letter in str_name:
        data += pack("B", ord(letter))
        data += pack("B", 0)

    return data


def to_lxml(record_xml):
    fin_xml = record_xml.encode("utf-8")
    parser = etree.XMLParser(resolve_entities=False)
    
    return etree.fromstring(fin_xml, parser)


def xml_records(filename):
    xdata = ""
    with open(filename, 'r', encoding="utf-8") as fx:
        for line in fx:
            xdata += line.replace("<?xml version=\"1.0\" encoding=\"utf-8\" standalone=\"yes\"?>", "").replace("</Events>", "").replace("<Events>", "")
        xml_list = re.split("<Event xmlns=[\'\"]http://schemas.microsoft.com/win/2004/08/events/event[\'\"]>", xdata)
        del xdata
        for xml in xml_list:
            if xml.strip().startswith("<System>"):
                try:
                    yield to_lxml("<?xml version=\"1.0\" encoding=\"utf-8\" standalone=\"yes\" ?><Event>" + xml), None
                except etree.XMLSyntaxError as e:
                    yield xml, e


def load_test_data(data):
    xdata = data.replace("<?xml version=\"1.0\" encoding=\"utf-8\" standalone=\"yes\"?>", "").replace("</Events>", "").replace("<Events>", "")
    xml_list = re.split("<Event xmlns=[\'\"]http://schemas.microsoft.com/win/2004/08/events/event[\'\"]>", xdata)
    for xml in xml_list:
        if xml.strip().startswith("<System>"):
            try:
                yield to_lxml("<?xml version=\"1.0\" encoding=\"utf-8\" standalone=\"yes\" ?><Event>" + xml), None
            except etree.XMLSyntaxError as e:
                yield xml, e


def getnttime(utime):
    mintime = time.mktime(utime.timetuple())
    namintime = int(mintime + 11644473600)
    nowTime = lambda: int(round(namintime * 10000000))
    return nowTime()


# SDBM Hash
def calc_name_hash(str_name):
    hashVal = 0
    for i in range(len(str_name)):
        hashVal = hashVal * 65599 + ord(str_name[i])

    return hashVal & 0xffff


def create_event_details(node_1st_element) -> bytes:
    """
    Create event details from the given node.

    Args:
        node_1st_element (xml.etree.ElementTree.Element): An XML node containing the first-level element.

    Returns:
        bytes: Binary data representing the event details.
    """

    event_details = b""
    for node_2nd_element in node_1st_element:
        event_details_data = create_name_chunk(node_2nd_element.tag)
        if node_2nd_element.text:
            token_close = TOKEN_TYPE["BinXmlTokenEndElementTag"]
            value_text = pack("B", TOKEN_TYPE["BinXmlTokenCloseStartElementTag"]) + create_value_chunk(node_2nd_element.text)
        else:
            token_close = TOKEN_TYPE["BinXmlTokenCloseEmptyElementTag"]
            value_text = b""

        if node_2nd_element.attrib:
            token_start = TOKEN_TYPE["BinXmlTokenOpenStartElementTag_Attribute"]
            event_details_data += create_attribute_chunk(node_2nd_element.attrib)
            event_details_data += value_text
            event_details_data += pack("B", token_close)
            event_details += element_start(event_details_data, token_start)
        else:
            token_start = TOKEN_TYPE["BinXmlTokenOpenStartElementTag_noAttribute"]
            event_details_data += value_text
            event_details_data += pack("B", token_close)
            event_details += element_start(event_details_data, token_start)

    return event_details


def process_nodes(node) -> bytes:
    """
    Process the given node and create BinXML chunks.

    Args:
        node (xml.etree.ElementTree.Element): An XML node to be processed.

    Returns:
        bytes: BinXML chunks generated from the input node.
    """

    binxml_chunk = b""
    for node_1st_element in node:
        event_details = create_event_details(node_1st_element)

        binxml_1st_chunk = create_name_chunk(node_1st_element.tag)
        binxml_1st_chunk += pack("B", TOKEN_TYPE["BinXmlTokenCloseStartElementTag"])
        binxml_chunk += element_start(binxml_1st_chunk + event_details, TOKEN_TYPE["BinXmlTokenOpenStartElementTag_noAttribute"])
        binxml_chunk += pack("B", TOKEN_TYPE["BinXmlTokenEndElementTag"])

    return binxml_chunk


def convert_xml_to_binxml(node, event_number) -> bytes:
    """
    Convert the given XML node to BinXML data.

    Args:
        node (xml.etree.ElementTree.Element): An XML node to be converted.

    Returns:
        bytes: BinXML data generated from the input node.
    """
    binxml_chunk = process_nodes(node)

    binxml_event = create_name_chunk("Event")
    binxml_event += create_attribute_chunk({"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"})
    binxml_event += pack("B", TOKEN_TYPE["BinXmlTokenCloseStartElementTag"])
    binxml = element_start(binxml_event + binxml_chunk, TOKEN_TYPE["BinXmlTokenOpenStartElementTag_Attribute"])
    binxml += pack("B", TOKEN_TYPE["BinXmlTokenEndElementTag"])

    #if args.usetemplate:
    #    logger.info("use template instance.")
    #    binxml = create_template_definition(binxml)

    return create_event_record(binxml + pack("B", TOKEN_TYPE["BinXmlTokenEOF"]), event_number)


def create_template_definition(data: bytes) -> bytes:
    """
    Create a template definition using the given BinXML data.

    Args:
        data (bytes): BinXML data.

    Returns:
        bytes: Template definition created using the input BinXML data.
    """

    # set template instance
    template_header = pack("B", TOKEN_TYPE["BinXmlTokenTemplateInstance"])

    template_identifier_guid = uuid.uuid4().bytes
    for key, value in BINXML_TEMPLATE_DEFINITION.items():
        format_specifier, data_value = value
        if key == "data_size":
            data_value = len(data) + 5
        if key == "template_identifier_4":
            data_value = template_identifier_guid[:4]
        if key == "template_identifier":
            data_value = template_identifier_guid
        template_header += pack(format_specifier, data_value)

    # set fragment header
    template_header += pack(">I", FLAGMENT_HEADER)

    return template_header + data


def element_start(data: bytes, token_start: int) -> bytes:
    """
    Create an element start tag for the given BinXML data.

    Args:
        data (bytes): BinXML data.
        token_start (int): Token value for the element start tag.

    Returns:
        bytes: Element start tag created using the input data.
    """
    element_header = b""
    for key, value in BINXML_ELEMENT_START.items():
        format_specifier, data_value = value
        if key == "open_start_element_tag_token":
            data_value = token_start
        if key == "data_size":
            data_value = len(data) + 4 # Size from element_name_offset to the end (end of tag)
        element_header += pack(format_specifier, data_value)

    return element_header + data


def create_name_chunk(name_element: str) -> bytes:
    """
    Create a name chunk for the given BinXML data.

    Args:
        name_element (str): Name element.

    Returns:
        bytes: Name chunk created using the input data.
    """
    binxml_name_data = b""
    for key, value in BINXML_NAME.items():
        format_specifier, data_value = value
        if key == "name_hash":
            data_value = calc_name_hash(name_element)
        elif key == "number_of_characters":
            data_value = len(name_element)
        binxml_name_data += pack(format_specifier, data_value)
    
    binxml_name_data += to_wordpack(name_element)
    binxml_name_data += pack("H", 0) # end of BinXML

    return binxml_name_data


def create_value_chunk(value_element: str) -> bytes:
    """
    Create a value chunk for the given BinXML data.

    Args:
        value_element (str): Value element.

    Returns:
        bytes: Value chunk created using the input data.
    """
    binxml_value_text_data = b""
    for key, value in BINXML_VALUE_TEXT.items():
        format_specifier, data_value = value
        if key == "data_size":
            data_value = len(value_element)
        binxml_value_text_data += pack(format_specifier, data_value)
    
    binxml_value_text_data += to_wordpack(value_element)

    return binxml_value_text_data


def create_attribute_chunk(attribute_element_dict: dict) -> bytes:
    """
    Create an attribute chunk for the given BinXML data.

    Args:
        attribute_element_dict (dict): Dictionary of attribute name-value pairs.

    Returns:
        bytes: Attribute chunk created using the input data.
    """
    binxml_attribute_data = b""
    for count, (attribute_name, attribute_value) in enumerate(attribute_element_dict.items()):
        if count == len(attribute_element_dict) - 1:
            attribute_token = TOKEN_TYPE["BinXmlTokenAttribute"]
        else:
            attribute_token = TOKEN_TYPE["BinXmlTokenAttribute_Next"]

        for key, value in BINXML_ATTRIBUTE.items():
            format_specifier, data_value = value
            if key == "attribute_token":
                data_value = attribute_token
            binxml_attribute_data += pack(format_specifier, data_value)

        binxml_attribute_data += create_name_chunk(attribute_name)
        binxml_attribute_data += create_value_chunk(attribute_value)

    binxml_attribute_data_len = pack("I", len(binxml_attribute_data))

    return binxml_attribute_data_len + binxml_attribute_data


def create_evtx(data: bytes, event_count: int, chunk_count: int) -> bytes:
    """
    Create an Evtx header for the given data.

    Args:
        data (bytes): The contents of the Evtx file.
        event_count (int): The number of events in the Evtx file.
        chunk_count (int): The number of chunks in the Evtx file.

    Returns:
        bytes: The Evtx header and data.
    """
    evtx_header = b""

    for key, value in EVTX_HEADER.items():
        format_specifier, data_value = value
        if key == "next_record_identifier":
            data_value = START_EVENT_RECORD_ID + event_count
        elif key == "last_chunk_number":
            data_value = chunk_count
        elif key == "number_of_chunks":
            data_value = chunk_count + 1
        elif key == "checksum":
            data_value = zlib.crc32(evtx_header[:120])
        evtx_header += pack(format_specifier, data_value)

    return evtx_header + data


def create_evtx_chunk(data: bytes, event_count: int) -> bytes:
    """
    Create a chunk header for the Evtx file.

    Args:
        data (bytes): The event data to be included in the chunk.
        event_count (int): The count of events to be included in the chunk.

    Returns:
        bytes: The chunk header and event data as bytes.
    """
    evtx_chunk_header = b""

    # Set last_event_record_number and free_space_offset
    last_event_record_number = START_EVENT_RECORD_ID + event_count - 1
    free_space_offset = len(data) + 0x0200 # Junk data offset from 0x1000

    for key, value in EVTX_CHUNK_HEADER.items():
        format_specifier, data_value = value
        if key == "last_event_record_number":
            data_value = event_count
        elif key == "last_event_record_identifier":
            data_value = last_event_record_number
        elif key == "free_space_offset":
            data_value = free_space_offset
        elif key == "event_records_checksum":
            data_value = zlib.crc32(data) # CRC32 from 0x1200 to free_space_offset
        elif key == "checksum":
            # Add Common string offset array after 128 bytes
            common_string_offset = pack("12s", b'\00')
            common_string_offset += pack("H", 0)
            common_string_offset += pack("370s", b'\00')
            data_value = zlib.crc32(evtx_chunk_header[:120] + common_string_offset)
        evtx_chunk_header += pack(format_specifier, data_value)

    evtx_chunk = evtx_chunk_header + common_string_offset

    return evtx_chunk + data


def create_chunk(binxml: bytes, total_event_count: int, total_chunk_count: int) -> bytearray:
    """
    Create a chunk for the Evtx file.

    Args:
        binxml (bytes): The binary data of an event record.
        total_event_count (int): The total event count.
        total_chunk_count (int): The total chunk count.

    Returns:
        bytearray: The binary data of a chunk.
    """

    binxml_array = fix_binxml_offset(binxml)
    evtx_chunk_part = create_evtx_chunk(binxml_array, total_event_count)

    set_blank_len = MAX_CHUNK_SIZE - len(evtx_chunk_part)
    evtx_chunk_part += pack("{}s".format(set_blank_len), b'\00')

    # replace last_event_record_offset
    evtx_chunk_array = bytearray(evtx_chunk_part)
    pattern = rb'\x2a\x2a\x00\x00'
    results = re.finditer(pattern, evtx_chunk_part)
    for result in results:
        pass
    offset = pack("I", result.start())
    for i in range(4):
        evtx_chunk_array[0x2c + i] = offset[i]

    # replace event_records_checksum
    evtx_chunk_hash = pack("I", zlib.crc32(evtx_chunk_array[:120] + evtx_chunk_array[128:512]))
    for i in range(4):
        evtx_chunk_array[124 + i] = evtx_chunk_hash[i]

    return evtx_chunk_array


def fix_binxml_offset(binxml: bytes) -> bytearray:
    """
    Fixed offset element name and attribute name.

    Args:
        binxml (bytes): The binary data of an event record.

    Returns:
        bytearray: Fixed binary data of a event record.
    """

    # replace element_name_offset
    binxml_array = bytearray(binxml)
    pattern_element = re.compile(b'\x99\x99\x99\x99')
    results = pattern_element.finditer(binxml)
    for result in results:
        offset = pack("I", result.start() + 0x204)
        for i in range(4):
            binxml_array[result.start() + i] = offset[i]

    # replace attribute_name_offset
    pattern_attribute = re.compile(b'\x88\x88\x88\x88')
    results = pattern_attribute.finditer(binxml)
    for result in results:
        offset = pack("I", result.start() + 0x204)
        for i in range(4):
            binxml_array[result.start() + i] = offset[i]

    # replace template_definition_data_offset
    #pattern_attribute = re.compile(b'\x77\x77\x77\x77')
    #results = pattern_attribute.finditer(binxml)
    #for result in results:
    #    offset = pack("I", result.start() + 0x204)
    #    for i in range(4):
    #        binxml_array[result.start() + i] = offset[i]

    return binxml_array


def create_event_record(data: bytes, count: int) -> bytes:
    """
    Create fragment event records.

    Args:
        data (bytes): The binary data of an event record.
        count (int): The count of events.

    Returns:
        bytes: The binary data of an event record with a size copy at the end.
    """
    event_record = b""

    for key, value in EVTX_EVENT_RECORD_HEADER.items():
        format_specifier, data_value = value
        if key == "size":
            data_value = len(data) + 0x20 # Size from EVTX_EVENT_RECORD_HEADER_SIGNATURE to size copy
        elif key == "identifier":
            data_value = START_EVENT_RECORD_ID + count - 1
        elif key == "written_time":
            data_value = getnttime(datetime.now())
        event_record += pack(format_specifier, data_value)

    event_record += pack(">I", FLAGMENT_HEADER)

    return event_record + data + pack("I", len(data) + 0x20) # Add a copy of the size to the end


def process_xml_data(xml_data: str) -> tuple:
    """
    Process the given test data and return the total event count and BinXML data.

    Args:
        test_data (str): Path to the test data file.

    Returns:
        tuple: A tuple containing the total event count (int) and BinXML data (bytes).
    """

    total_event_count = 0
    binxml = b""
    evtx_chunk = b""
    for node, err in load_test_data(xml_data):
        if err is not None:
            continue
        total_event_count += 1
        binxml += convert_xml_to_binxml(node, total_event_count)  # Convert XML to BinXML

    evtx_chunk += create_chunk(binxml, total_event_count, 0)

    return total_event_count, 0, evtx_chunk


def leer_evento_xml(nombre_xml, directorio):
    ruta_archivo: Path = Path(directorio) / nombre_xml

    content = ruta_archivo.read_text()

    event_count, chunk_count, evtx_chunk = process_xml_data(content)

    return evtx_chunk, event_count, chunk_count    

def generar_archivo_evtx(nombre_evtx, directorio, data, chunk_count, event_count):
    """
    Genera un archivo .evtx binario sintético y correlacionado con los eventos del sistema
    (como EventID 4624, 7045, 4672, 1102) para su análisis con evtx_dump o python-evtx.
    """
    artMan = artifact.ArtifactManager()
    ruta_archivo = artMan.create_file(nombre_evtx, directorio)

    evtx_data = create_evtx(data, event_count, chunk_count)

    with ruta_archivo.open("wb") as f:
        f.write(evtx_data)

    sha256_evtx = hashlib.sha256(evtx_data).hexdigest()

    module_logger.info(f"Objeto evtx: {nombre_evtx} creado. SHA256: {sha256_evtx}")
    return sha256_evtx
    
import binascii
import io
from math import ceil
import struct

from .constants import *

def decompress_lz4(f, min_decode_length):
	data_decompress = b""
	d_offset = 0
	dest_end = min_decode_length + 7

	f_start = f.tell()
	while True:
		token = intfy(f.read(1))
		literal_len = token >> 4

		if literal_len != 0:
			if literal_len == 0xf:
				_len = intfy(f.read(1))
				while _len == 0xff:
					literal_len += 255
					_len = intfy(f.read(1))
				literal_len += _len
			data_decompress += f.read(literal_len)
			d_offset += literal_len

		if d_offset >= min_decode_length:
			break

		match_dec_low = intfy(f.read(1))
		match_dec_high = intfy(f.read(1)) << 8
		# matches
		match_dec = match_dec_low | match_dec_high
		assert match_dec > 0

		match_len = token & 0xf
		if match_len == 0xf:
			_len = intfy(f.read(1))
			while _len == 0xff:
				match_len += 255
				_len = intfy(f.read(1))
			match_len += _len

		match_len += MIN_MATCH
		fast_len = (match_len + 7) & 0xfffffff8

		if match_dec < match_len or (d_offset + fast_len) > dest_end:
			ref = d_offset - match_dec
			end = d_offset + match_len
			while d_offset < end:
				data_decompress += bytes([data_decompress[ref]])
				ref += 1
				d_offset += 1
		else:
			# Skip fast copy, it should be doable to implement
			data_decompress += data_decompress[d_offset - match_dec:d_offset - match_dec + match_len]
			d_offset += match_len

		if d_offset >= min_decode_length:
			break

	return data_decompress, d_offset

def read_long(f):
	return intfy(f.read(8))

def read_int(f):
	return intfy(f.read(4))

def read_byte(f):
	return intfy(f.read(1))

def read_string(f):
	str_length = read_vint(f)
	# if str_length > 127:
		# raise Exception("code not dealing with variable byte yet")
	name = str(f.read(str_length), 'utf-8')
	return name

def byte_count(value_count, bits_per_value):
	return int(ceil(float(value_count) * float(bits_per_value) / 8))

def long_count(value_count, bits_per_value):
	return int(ceil(float(byte_count(value_count, bits_per_value)) / 8))

def floatfy(str_bytes):
	return struct.unpack("f", str_bytes)[0]

def doublefy(str_bytes):
	return struct.unpack("d", str_bytes)[0]

def read_zfloat(f):
	b_byte = f.read(1)
	b = intfy(b_byte)
	if b == 0xff:
		return floatfy(f.read(4))
	elif (b & 0x80) != 0:
		return (b & 0x7f) - 1
	else:
		bits = b_byte + f.read(2) + f.read(1)
		return floatfy(bits)

def read_tlong(f):
	header = intfy(f.read(1))
	bits = header & 0x1f
	if (header & 0x20) != 0:
		bits = bits | (read_vlong(f) << 5)

	l = zigzag_decode(bits)

	encoding = header & DAY_ENCODING
	if encoding == SECOND_ENCODING:
		l = l * SECOND
	elif encoding == HOUR_ENCODING:
		l = l * HOUR
	elif encoding == DAY_ENCODING:
		l = l * DAY
	elif encoding == 0:
		pass
	else:
		raise Exception("Unknown date type")

	return l

def read_zdouble(f):
	b_byte = f.read(1)
	b = intfy(b_byte)

	if b == 0xff:
		return doublefy(f.read(8))
	elif b == 0xfe:
		return floatfy(f.read(4))
	elif (b & 0x80) != 0:
		return (b & 0x7f) - 1
	else:
		bits = b_byte + f.read(4) + f.read(2) + f.read(1)
		return doublefy(bits)


# 128	10000000	00000001	
# 129	10000001	00000001
# 16,384	10000000	10000000	00000001
def read_vint(f):
	total = 0
	val = intfy(f.read(1))
	if val < 2 ** 7:
		return val
	total += val - 2**7

	val = intfy(f.read(1))
	if val < 2 ** 7:
		return total + 2**7 * val

	total += (val - 2**7) * 2**7

	val = intfy(f.read(1))
	if val < 2 ** 7:
		return total + 2**14 * val	
	total += (val - 2**7) * 2**14

	val = intfy(f.read(1))
	if val < 2 ** 7:
		return total + 2**21 * val	
	total += (val - 2**7) * 2**21

	val = intfy(f.read(1))
	if val < 2 ** 7:
		total = total + 2 ** 28 * val
		if total > 0xffffffff:
			raise Exception("unsupported range")
		return total
	else:
		raise Exception("unsupported range")

def read_vlong(f):
	total = 0
	val = intfy(f.read(1))
	if val < 2 ** 7:
		return val
	total += val - 2**7

	val = intfy(f.read(1))
	if val < 2 ** 7:
		return total + 2**7 * val

	total += (val - 2**7) * 2**7

	val = intfy(f.read(1))
	if val < 2 ** 7:
		return total + 2**14 * val	
	total += (val - 2**7) * 2**14

	val = intfy(f.read(1))
	if val < 2 ** 7:
		return total + 2**21 * val	
	total += (val - 2**7) * 2**21

	val = intfy(f.read(1))
	if val < 2 ** 7:
		return total + 2**28 * val	
	total += (val - 2**7) * 2**28

	val = intfy(f.read(1))
	if val < 2 ** 7:
		return total + 2**35 * val	
	total += (val - 2**7) * 2**35

	val = intfy(f.read(1))
	if val < 2 ** 7:
		return total + 2**42 * val	
	total += (val - 2**7) * 2**42

	val = intfy(f.read(1))
	if val < 2 ** 7:
		return total + 2**49 * val	
	total += (val - 2**7) * 2**49

	val = intfy(f.read(1))
	if val < 2 ** 7:
		return total + 2**56 * val	
	total += (val - 2**7) * 2**56

	# long is 8 bytes
	if total <= 0xffffffffffffffff:
		return total
	else:
		raise Exception("unsupported range")

def zigzag_decode(val):
	return (val >> 1) ^ (-(val & 1))

def read_string_set(f):
	set_size = read_vint(f)
	string_set = []
	# if set_size > 127:
		# raise Exception("code not dealing with variable byte yet")

	for i in range(set_size):
		string = read_string(f)
		string_set.append(string)
	return string_set

def read_string_map(f, v_int=True):
	if v_int:
		map_size = read_vint(f)
	else:
		map_size = intfy(f.read(4))

	string_map = {}
	for i in range(map_size):
		string_key = read_string(f)
		string_val = read_string(f)
		string_map[string_key] = string_val
	return string_map

def read_string_set_map(f, size):
	set_map = {}
	for i in range(size):
		index = intfy(f.read(4))
		val = read_string_set(f)
		set_map[index] = val

	return set_map

def read_byteref(f):
	length = read_vint(f)
	return f.read(length)


def hexify(bytes_string):
	# print(dir(bytes_string))
	return ':'.join(hex(x)[2:] for x in bytes_string)

def intfy(bytes_string):
	return int(bytes_string.hex(), 16)

def parse_header(f, suffix=True):
	# read the header of segment file
	header_magic = f.read(4)
	name = read_string(f)

	# version 6 means lucene codec53
	version = f.read(4)

	if not suffix:
		return header_magic, name, version
	# In the actual lucene segmentinfos code, the object id get toss away
	object_id = f.read(16)
	suffix_length = f.read(1)
	length = intfy(suffix_length)
	# todo: this is based 36 string, generation is checked against the expected generation
	generation = f.read(length)
	return header_magic, name, version, object_id, length, generation

def parse_version(f):
	# todo: this is variable byte format
	major = f.read(1)
	minor = f.read(1)
	bug = f.read(1)
	return intfy(major), intfy(minor), intfy(bug)

def parse_segment_info_version(f):
	major = f.read(4)
	minor = f.read(4)
	bug = f.read(4)
	return intfy(major), intfy(minor), intfy(bug)

def parse_footer(f):
	footer_magic = hexify(f.read(4))
	checksum_algo = intfy(f.read(4))
	checksum = hexify(f.read(8))
	return footer_magic, checksum_algo, checksum

def compute_checksum(f, offset=0, length=-1):
	# This should be the last step as it reset the file descriptor
	f.seek(offset)
	all_data = f.read(length)
	actual_checksum = binascii.crc32(all_data[:-8])
	return  hex(actual_checksum & 0xffffffff)

def pack64(f, num_values, bits_per_value):
	b_count = byte_count(num_values, bits_per_value)
	l_count = long_count(num_values, bits_per_value)
	
	blocks = []
	for i in range(int(b_count / 8)):
		# needs to convert it to bytes
		# blocks.append(hexify(f.read(8)))
		blocks.append(f.read(8))

	if (b_count % 8 != 0):
		# needs to convert it to bytes
		# blocks.append(hexify(f.read(b_count % 8)))
		blocks.append(f.read(b_count % 8))

	assert(len(blocks) == l_count)
	return blocks

def print_header(header_magic, name, version, object_id, suffix_length, generation):
	print("magic header: " + hexify(header_magic))
	print("segment codec: " + name)
	print("format version: " + str(intfy(version)))	
	print("object_id: " + hexify(object_id))
	print("suffix length: " + str(suffix_length))
	print("generation: " + str(generation))

def print_footer(footer_magic, checksum_algo, checksum, actual_checksum):
	print("Footer magic: {}".format(footer_magic))
	print("checksum algo: {}".format(checksum_algo))
	print("checksum expect: {}".format(checksum))
	print("checksum actual: {}".format(actual_checksum))

def read_field(docs_reader, field_info, bits):
	if bits == BYTE_ARR:
		byte_len = read_vint(docs_reader)
		val = docs_reader.read(byte_len)
	elif bits == STRING:
		byte_len = read_vint(docs_reader)
		val = docs_reader.read(byte_len)
	elif bits == NUMERIC_INT:
		val = zigzag_decode(read_vint(docs_reader))
	elif bits == NUMERIC_FLOAT:
		val = read_zfloat(docs_reader)
	elif bits == NUMERIC_LONG:
		val = read_tlong(docs_reader)
	elif bits == NUMERIC_DOUBLE:
		val = read_zdouble(docs_reader)
	else:
		raise Exception("unknown data type")

	return val

def parse_serialize_docs(docs, docs_count, doc_fields_count, doc_offets, fields_info, doc_base):
	docs_reader = io.BufferedReader(io.BytesIO(docs))

	for i in range(docs_count):
		print("current docs reader: {}".format(docs_reader.tell()))
		fields_count = doc_fields_count[i]
		doc = {}
		for j in range(fields_count):
			info_and_bits = read_vlong(docs_reader)
			field_number = info_and_bits >> 3 # bits required to store NUMERIC_DOUBLE 0x5
			field_info = fields_info[field_number]
			bits = info_and_bits & 7
			assert bits <= 0x5
			val = read_field(docs_reader, field_info, bits)
			doc[field_info["field_name"]] = val
		# print("parse serialize doc: {}: {}".format(doc_base + i, doc))

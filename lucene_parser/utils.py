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

def print_header(header_magic, name, version, object_id="", suffix_length="", generation=""):
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


def load_meta(f, num_values, block_shift):
	num_blocks = num_values >> block_shift
	if (num_blocks << block_shift) < num_values:
		num_blocks += 1
	
	meta = []
	for i in range(num_blocks):
		_mins = intfy(f.read(8))
		_avgs = floatfy(f.read(4))
		_offsets = intfy(f.read(8))
		_bpvs = intfy(f.read(1))
		meta.append({"mins": _mins,
			         "avgs": _avgs,
			         "offsets": _offsets,
			         "bpvs": _bpvs})
	return meta

def read_numeric_entry(f, info, segment_size):
	entry = {}
	entry_format = read_vint(f)
	missing_offset = read_long(f)
	# missing offset can be 0xffffffffffffffff == -1
	if entry_format == DOC_SPARSE_COMPRESSED:
		num_docs_with_value = read_vlong(f)
		block_shift = read_vint(f)
		meta = load_meta(f, num_docs_with_value, block_shift)
		entry["direct_addr_meta"] = meta

	entry["format"] = entry_format
	entry["missing_offset"] = missing_offset
	entry["offset"] = intfy(f.read(8))
	entry["count"] = read_vlong(f)

	if entry_format == DOC_CONST_COMPRESSED:
		min_value = intfy(f.read(8))
		entry["min_value"] = min_value
	elif entry_format == DOC_GCD_COMPRESSED:
		entry["min_value"] = intfy(f.read(8))
		entry["gcd"] = intfy(f.read(8))
		entry["bits_per_value"] = read_vint(f)
	elif entry_format == DOC_TABLE_COMPRESSED:
		unique_value = read_vint(f)
		if unique_value > 255:
			raise Exception("Table corrupted")
		table = []
		for i in range(unique_value):
			table.append(intfy(f.read(8)))
		entry["table"] = table
		entry["bits_per_value"] = read_vint(f)
	elif entry_format == DOC_DELTA_COMPRESSED:
		entry["min_value"] = intfy(f.read(8))
		entry["bits_per_value"] = read_vint(f)
		pass
	elif entry_format == DOC_MONOTONIC_COMPRESSED:
		block_shift = read_vint(f)
		meta = load_meta(f, segment_size, block_shift)
		entry["direct_addr_meta"] = meta
	elif entry_format == DOC_SPARSE_COMPRESSED:
		number_type = intfy(f.read(1))
		field_number = read_vint(f)
		assert(field_number == info["field_number"])
		dv_format = intfy(f.read(1))
		entry["non_missing_value"] = read_numeric_entry(f, info, segment_size)
	else:
		raise Exception("corrupted entry format")
	entry["end_offset"] = intfy(f.read(8))
	return entry
	

def read_binary_entry(f, info):
	entry = {}
	entry["format"] = read_vint(f)
	entry["missing_offset"] = intfy(f.read(8))
	entry["min_length"] = read_vint(f)
	entry["max_length"] = read_vint(f)
	entry["count"] = read_vlong(f)
	entry["offset"] = read_long(f)
	if entry["format"] == DOC_BINARY_FIXED_UNCOMPRESSED:
		pass
	elif entry["format"] == DOC_BINARY_PREFIX_COMPRESSED:
		entry["addr_offset"] = read_long(f)
		entry["pack_ints_version"] = read_vint(f)
		entry["block_size"] = read_vint(f)
		entry["reversed_index_offset"] = read_long(f)
	elif entry["format"] == DOC_BINARY_VARIABLE_UNCOMPRESSED:
		entry["addr_offset"] = read_long(f)
		block_shift = read_vint(f)
		meta = load_meta(f, entry["count"] + 1, block_shift)
		entry["direct_addr_meta"] = meta
		entry["addr_end_offset"] = read_long(f)
	else:
		raise Exception("Corrupted doc value format")
	return entry

def read_sorted_entry(f, info, segment_size):
	field_number = read_vint(f)
	if field_number != info["field_number"]:
		raise Exception("corrupted field number")

	doc_value_format = intfy(f.read(1))
	if doc_value_format != DOC_VALUES_BINARY:
		raise Exception("corrupted doc value format")

	binary_entry = read_binary_entry(f, info)

	field_number = read_vint(f)
	if field_number != info["field_number"]:
		raise Exception("corrupted field number")
	doc_value_format = intfy(f.read(1))
	if doc_value_format != DOC_VALUES_NUMERIC:
		raise Exception("corrupted doc value format")
	ord_entry = read_numeric_entry(f, info, segment_size)

	return binary_entry, ord_entry

def read_sorted_set_entry(f, info):
	entry = {}
	entry["format"] = read_vint(f)
	if entry["format"] == DOC_SORTED_SET_TABLE:
		table_length = read_int(f)
		if table_length > 256:
			raise Exception("data corrupted")

		for i in range(table_length):
			entry[i] = read_long(f)

		table_size = read_int(f)
		if table_size > table_length + 1:
			raise Exception("data corrupted")

		table_offsets = [0] * (table_size + 1)
		for i in range(1, table_size + 1):
			table_offsets[i] = table_offsets[i - 1] + read_int(f)

		entry["table_offsets"] = table_offsets

	elif entry["format"] != DOC_SORTED_SINGLE_VALUED and entry["format"] != DOC_SORTED_WITH_ADDRESSES:
		raise Exception("data corrupted")

	return entry

def read_sorted_set_field_with_addr(f, info):
	if read_vint(f) != info["field_number"]:
		raise Exception("data corrupted")
	if read_byte(f) != DOC_VALUES_BINARY:
		raise Exception("data corrupted")

	binary_entry = read_binary_entry(f, info)

	if read_vint(f) != info["field_number"]:
		raise Exception("data corrupted")
	if read_byte(f) != DOC_VALUES_BINARY:
		raise Exception("data corrupted")

	ord_entry = read_numeric_entry(f, info)

	if read_vint(f) != info["field_number"]:
		raise Exception("data corrupted")
	if read_byte(f) != DOC_VALUES_BINARY:
		raise Exception("data corrupted")

	ord_index_entry = read_numeric_entry(f, info)
	return binary_entry, ord_entry, ord_index_entry

def read_sorted_set_field_with_table(f, info):
	if read_vint(f) != info["field_number"]:
		raise Exception("data corrupted")
	if read_byte(f) != DOC_VALUES_BINARY:
		raise Exception("data corrupted")

	binary_entry = read_binary_entry(f, info)

	if read_vint(f) != info["field_number"]:
		raise Exception("data corrupted")
	if read_byte(f) != DOC_VALUES_BINARY:
		raise Exception("data corrupted")

	ord_entry = read_numeric_entry(f, info)
	return binary_entry, ord_entry

def get_live_bits(offset, count):
	if offset == 0xffffffffffffffff:
			# all lived, always return True
		return {"format": "ALL_LIVE"}
	elif offset == 0xfffffffffffffffe:
		# all missing, always return False
		return {"format": "ALL_MISSING"}
	else:
		# random sliced the data
		length = (count + 7) >> 3
		f_doc_data.seek(f_doc_offset + offset)
		live_data = f_doc_data.read(length)
		live_reader = io.BufferedReader(io.BytesIO(live_data))
		return {"live_reader": live_reader, "format": "MIXED"}

# needs to implement other doc values types 
def get_docs_with_field(field_entry_map, max_doc, f_doc_data, f_doc_offset):
	# Needs to implemented it next
	for _field, _data in field_entry_map.items():
		field_info = _data["info"]
		doc_values_type = field_info["field_type"]

		if doc_values_type == DOC_VALUES_SORTED_SET:
			sorted_set = get_sorted_set(_data, f_doc_data, f_doc_offset, max_doc)
			# print("_field sorted_set: {}, doc_values {}".format(_field, sorted_set))
			# raise Exception("")
		elif doc_values_type == DOC_VALUES_SORTED_NUMERIC:
			sorted_numeric, live_bits = get_sorted_numeric(_data, f_doc_data, f_doc_offset, max_doc)
			# print("_field sorted_numeric: {}, doc_values {}, live_bits {}".format(_field, sorted_numeric, live_bits))
		elif doc_values_type == DOC_VALUES_SORTED:
			sorted_values = get_sorted(_data, f_doc_data, f_doc_offset)
			# print("_field sorted: {}, doc_values {}".format(_field, sorted_values))
		elif doc_values_type == DOC_VALUES_BINARY:
			binary = get_binary(_data, f_doc_data, f_doc_offset)
			# print("_field binary: {}, doc_values {}".format(_field, binary))
		elif doc_values_type == DOC_VALUES_NUMERIC:
			entry = _data["numeric"]
			if entry["format"] == DOC_SPARSE_COMPRESSED:
				raise Exception("todo: not implemented")
			else:
				live_bits = get_live_bits(entry["missing_offset"], max_doc)
				live_bits["constant"] = entry["min_value"]
			# print("_field values numeric {}, doc_values {}".format(_field, live_bits))
		else:
			raise Exception("unkown doc values type")


def get_binary(entry, f_doc_data, f_doc_offset):
	_format = entry["format"]
	if _format == DOC_BINARY_FIXED_UNCOMPRESSED:
		offset = entry["offset"]
		length = entry["count"] * entry["max_length"]
		# seek f_doc_data to beginning of binary_blob
		f_doc_data.seek(f_doc_offset + offset)
		bin_blob = f_doc_data.read(length)
		# print "binary blob: ", bin_blob

		# data seek using getFixedBinary.LongBinaryDocValues
		bin_reader = io.BufferedReader(io.BytesIO(bin_blob))
		return {"reader": bin_reader, "length": entry["max_length"], "binary_blob": bin_blob, "format": _format}

	elif _format == DOC_BINARY_VARIABLE_UNCOMPRESSED:
		addr_offset = entry["addr_offset"]
		addr_end_offset = entry["addr_end_offset"]

		f_doc_data.seek(f_doc_offset + addr_offset)
		addresses_data = f_doc_data.read(addr_end_offset - addr_offset)
		addresses_reader = io.BufferedReader(io.BytesIO(addresses_data))

		offset = entry["offset"]
		f_doc_data.seek(f_doc_offset + offset)
		data = f_doc_data.read(addr_offset - offset)
		data_reader = io.BufferedReader(io.BytesIO(data))

		return {"addresses_reader": addresses_reader, "addresses_data": addresses_data, "data": data,
		        "data_reader": data_reader, "format": _format, "max_length": entry["max_length"]}

	elif _format == DOC_BINARY_PREFIX_COMPRESSED:
		raise Exception("todo: needs to implement")
	else:
		raise Exception("unkown format")

def get_numeric(entry, f_doc_data, f_doc_offset):
	_format = entry["format"]
	if _format == DOC_CONST_COMPRESSED:
		constant = entry["min_value"]
		missing_offset = entry["missing_offset"]
		count = entry["count"]

		if missing_offset == 0xffffffffffffffff:
			# all lived, always return True
			return {"constant": constant, "missing": "ALL_LIVE", "format": _format}
		elif missing_offset == 0xfffffffffffffffe:
			# all missing, always return False
			return {"constant": 0, "missing": "ALL_MISSING", "format": _format}
		else:
			# random sliced the data
			length = (count + 7) >> 3
			f_doc_data.seek(f_doc_offset + missing_offset)
			live_data = f_doc_data.read(length)
			live_reader = io.BufferedReader(io.BytesIO(live_data))
			return {"live_reader": live_reader, "constant": constant, "missing": None, "format": _format}

	elif _format == DOC_DELTA_COMPRESSED:
		# set the file pointer
		f_doc_data.seek(f_doc_offset + entry["offset"])
		length = entry["end_offset"] - entry["offset"]
		numeric_blob = f_doc_data.read(length)
		numeric_reader = io.BufferedReader(io.BytesIO(numeric_blob))
		delta = entry["min_value"]

		bits_per_value = entry["bits_per_value"]

		# there is three extra bytes get appended at the end
		# https://github.com/apache/lucene-solr/blob/branch_6_6/lucene/core/src/java/org/apache/lucene/util/packed/DirectWriter.java

		# needs to implement the data encoding when implements the actual data retrieving
		# if bits_per_value != 1:
		# 	raise Exception("todo: needs to implemented bits_per_value {}".format(bits_per_value))

		return {"delta": delta, "bits_per_value": bits_per_value, "numeric_reader": numeric_reader, "numeric_blob": numeric_blob, "length": length, "format": _format}

	elif _format == DOC_GCD_COMPRESSED:
		raise Exception("todo: needs to implement")
	elif _format == DOC_TABLE_COMPRESSED:
		raise Exception("todo: needs to implement")
	elif _format == DOC_SPARSE_COMPRESSED:
		raise Exception("todo: needs to implement")


def get_sorted(entries, f_doc_data, f_doc_offset):
	value_count = entries["binary"]["count"]
	binary_doc_values = get_binary(entries["binary"], f_doc_data, f_doc_offset)
	long_values_ordinals = get_numeric(entries["ord"], f_doc_data, f_doc_offset)
	return {"value_count": value_count, "binary_doc_values": binary_doc_values, "long_values_ordinals": long_values_ordinals}
	

def get_sorted_numeric(entries, f_doc_data, f_doc_offset, max_doc):
	# print("get sorted numeric {}".format(entries))
	sorted_set_entry = entries["ss"]
	_format = sorted_set_entry["format"]
	if _format == DOC_SORTED_SINGLE_VALUED:
		numeric_entry = entries["numeric"]
		numeric_values = get_numeric(numeric_entry, f_doc_data, f_doc_offset)
		
		if numeric_entry["format"] == DOC_SPARSE_COMPRESSED:
			raise Exception("not implemented")
		else:
			live_bits = get_live_bits(numeric_entry["missing_offset"], max_doc)

		return numeric_values, live_bits

	elif _format == DOC_SORTED_WITH_ADDRESSES:
		pass
	elif _format == DOC_SORTED_SET_TABLE:
		pass
	else:
		raise Exception("unknown format")


# Todo create direct reader for each bit
def read_sorted_set(sorted_doc_values, max_doc):
	value_count = sorted_doc_values["value_count"]
	binary_doc_values = sorted_doc_values["binary_doc_values"]
	long_values_ordinals = sorted_doc_values["long_values_ordinals"]
	ord_format = long_values_ordinals["format"]
	bits_per_value = long_values_ordinals["bits_per_value"]
	# print("long values format {}, bits_per_value {}".format(ord_format, bits_per_value))
	if ord_format == DOC_BINARY_FIXED_UNCOMPRESSED:
		pass
	elif ord_format == DOC_DELTA_COMPRESSED:
		# needs to get reader for each bits value
		if bits_per_value == 1:
			pass
		elif bits_per_value == 4:
			pass
		elif bits_per_value == 12:
			pass


def get_sorted_set(entries, f_doc_data, f_doc_offset, max_doc):
	entry = entries["ss"]
	_format = entry["format"]
	if _format == DOC_SORTED_SINGLE_VALUED:
		# print("entry: {}".format(entries))
		sorted_doc_values = get_sorted(entries, f_doc_data, f_doc_offset)
		read_sorted_set(sorted_doc_values, max_doc)
		return sorted_doc_values
	elif _format == DOC_SORTED_WITH_ADDRESSES:
		raise Exception("not implemented")
	elif _format == DOC_SORTED_SET_TABLE:
		raise Exception("not implemented")
	else:
		raise Exception("invalid doc value format")


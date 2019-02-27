import binascii
import io
from math import ceil
import struct
import os
import copy
import json

MIN_MATCH = 4

STRING = 0x0
BYTE_ARR = 0x01
NUMERIC_INT = 0x02
NUMERIC_FLOAT = 0x03
NUMERIC_LONG = 0x04
NUMERIC_DOUBLE = 0x05

SECOND = 1000
HOUR = 60 * 60 * SECOND
DAY = 24 * HOUR
SECOND_ENCODING = 0x40
HOUR_ENCODING = 0x80
DAY_ENCODING = 0xC0
BLOCK_SIZE = 128

INDEX_OPTION_NONE = 0
INDEX_OPTION_DOCS = 1
INDEX_OPTION_DOCS_FREQS = 2
INDEX_OPTION_DOCS_FREQS_POSITIONS = 3
INDEX_OPTION_DOCS_FREQS_POSITIONS_OFFSETS = 4

DOC_VALUES_NUMERIC = 0
DOC_VALUES_BINARY = 1
DOC_VALUES_SORTED = 2
DOC_VALUES_SORTED_SET = 3
DOC_VALUES_SORTED_NUMERIC = 4

DOC_DELTA_COMPRESSED = 0
DOC_GCD_COMPRESSED = 1
DOC_TABLE_COMPRESSED = 2
DOC_MONOTONIC_COMPRESSED = 3
DOC_CONST_COMPRESSED = 4
DOC_SPARSE_COMPRESSED = 5

DOC_BINARY_FIXED_UNCOMPRESSED = 0
DOC_BINARY_VARIABLE_UNCOMPRESSED = 1
DOC_BINARY_PREFIX_COMPRESSED = 2

DOC_SORTED_WITH_ADDRESSES = 0
DOC_SORTED_SINGLE_VALUED = 1
DOC_SORTED_SET_TABLE = 2

STORE_TERMVECTOR = 0x1
OMIT_NORMS = 0x2
STORE_PAYLOADS = 0x4


def decompress_lz4(f, min_decode_length):
	data_decompress = ""
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
				data_decompress += data_decompress[ref]
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

	name = ""
	for i in xrange(str_length):
		char = f.read(1)
		name += char

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

	for i in xrange(set_size):
		string = read_string(f)
		string_set.append(string)
	return string_set

def read_string_map(f, v_int=True):
	if v_int:
		map_size = read_vint(f)
	else:
		map_size = intfy(f.read(4))

	string_map = {}
	for i in xrange(map_size):
		string_key = read_string(f)
		string_val = read_string(f)
		string_map[string_key] = string_val
	return string_map

def read_string_set_map(f, size):
	set_map = {}
	for i in xrange(size):
		index = intfy(f.read(4))
		val = read_string_set(f)
		set_map[index] = val

	return set_map

def read_byteref(f):
	length = read_vint(f)
	return f.read(length)


def hexify(bytes_string):
	return ':'.join(x.encode('hex') for x in bytes_string)

def intfy(bytes_string):
	return int(bytes_string.encode('hex'), 16)

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
	for i in xrange(b_count / 8):
		blocks.append(hexify(f.read(8)))

	if (b_count % 8 != 0):
		blocks.append(hexify(f.read(b_count % 8)))

	assert(len(blocks) == l_count)
	return blocks

def print_header(header_magic, name, version, object_id, suffix_length, generation):
	print "magic header: ", hexify(header_magic)
	print "segment codec: ", name
	print "format version: ", hexify(version)
	print "object_id: ", hexify(object_id)
	print "suffix length: ", suffix_length
	print "generation: ", generation

def print_footer(footer_magic, checksum_algo, checksum, actual_checksum):
	print "Footer magic: ", footer_magic
	print "checksum algo: ", checksum_algo
	print "checksum expect: ", checksum
	print "checksum actual", actual_checksum


def parse_segment(segment_file):
	with open(segment_file, "rb") as f:
		# read the header of segment file
		yield parse_header(f)

		major, minor, bug = parse_version(f)
		yield major, minor, bug

		# counter tracks document add, delete
		index_update_count = f.read(8)
		yield intfy(index_update_count)

		name_counter = f.read(4)
		yield intfy(name_counter)

		segment_count = intfy(f.read(4))
		yield segment_count

		major = f.read(1)
		minor = f.read(1)
		bug = f.read(1)
		yield intfy(major), intfy(minor), intfy(bug)

		for i in xrange(segment_count):
			seg_name = read_string(f)
			has_segment = hexify(f.read(1))
			segment_id = hexify(f.read(16))
			# codec of actual lucene segment file
			seg_codec = read_string(f)
			del_gen = hexify(f.read(8))
			del_count = intfy(f.read(4))
			field_info_gen = hexify(f.read(8))
			doc_values_gen = hexify(f.read(8))

			# This header isn't documented
			field_info_files = read_string_set(f)
			dv_field_count = intfy(f.read(4))
			if dv_field_count == 0:
				yield seg_name, has_segment, segment_id, seg_codec, del_gen, del_count, field_info_gen, doc_values_gen, field_info_files, dv_field_count
			else:
				dv_fields = read_string_set_map(f, dv_field_count)
				yield seg_name, has_segment, segment_id, seg_codec, del_gen, del_count, field_info_gen, doc_values_gen, field_info_files, dv_field_count, dv_fields

		user_data = read_string_map(f)
		yield user_data

		footer_magic, checksum_algo, checksum = parse_footer(f)
		yield footer_magic, checksum_algo, checksum
		yield compute_checksum(f)

def parse_segment_info(_file):
	with open(_file, "rb") as f:
		yield parse_header(f)
		
		yield parse_segment_info_version(f)
		
		segment_size = intfy(f.read(4))
		yield segment_size

		is_compound_file = hexify(f.read(1))
		yield is_compound_file

		diagnostics = read_string_map(f)
		yield diagnostics

		set_files = read_string_set(f)
		yield set_files

		attributes = read_string_map(f)
		yield attributes

		num_sort_fields = read_vint(f)
		yield num_sort_fields

		if num_sort_fields > 0:
			raise Exception("Not implemented yet")

		yield parse_footer(f)
		yield compute_checksum(f)

def parse_cfe(_file):
	with open(_file + ".cfe", "rb") as f:
		yield parse_header(f)
		num_files = read_vint(f)
		yield num_files

		file_map = {}
		for i in xrange(num_files):
			file_name =  read_string(f)
			data_offset = intfy(f.read(8))
			data_length = intfy(f.read(8))
			file_map[file_name] = {"offset": data_offset, "length": data_length}

		yield file_map

def parse_fields(f, offset, length):
	f.seek(offset)
	header_magic, name, version, object_id, suffix_length, generation = parse_header(f)
	print_header(header_magic, name, version, object_id, suffix_length, generation)
	fields_count = read_vint(f)
	print "fields count: ", fields_count

	fields = {}
	for i in xrange(fields_count):
		print "========================================================================="
		field_name = read_string(f)
		print "field_name: ", field_name
		field_number = read_vint(f)
		print "field_number: ", field_number
		field_bits = f.read(1)
		print "field_bits: ", hexify(field_bits)

		store_term_vec = intfy(field_bits) & STORE_TERMVECTOR != 0
		omit_norm = intfy(field_bits) & OMIT_NORMS != 0
		store_payload = intfy(field_bits) & STORE_PAYLOADS != 0
		print "store_term_vec: {}, omit_norm {}, store_payload {}".format(store_term_vec, omit_norm, store_payload)

		index_option_bits = f.read(1)
		print "index_option_bits: ", hexify(index_option_bits)
		doc_values_bits = f.read(1)
		print "doc_values_bits: ", hexify(doc_values_bits)
		doc_values_gen = hexify(f.read(8))
		print "doc_values_gen: ", doc_values_gen
		attributes = read_string_map(f)
		print "attributes: ", attributes
		dimension_count = read_vint(f)
		print "dimension_count: ", dimension_count
		if dimension_count != 0:
			dimension_member_bytes = read_vint(f)
			print "dimension member bytes: ", dimension_member_bytes

		fields[field_number] = {
			"field_name": field_name,
			"field_number": field_number,
			"field_bits": intfy(field_bits),
			"index_option_bits": intfy(index_option_bits),
			"doc_values_bits": intfy(doc_values_bits),
			"doc_values_gen": doc_values_gen,
			"attributes": attributes,
			"dimension_count": dimension_count,
			"store_term_vec": store_term_vec,
			"omit_norm": omit_norm,
			"store_payload": store_payload
		}

	footer_magic, checksum_algo, checksum = parse_footer(f)
	actual_checksum = compute_checksum(f, offset, length)
	print_footer(footer_magic, checksum_algo, checksum, actual_checksum)
	return fields


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

def parse_serialize_docs(docs, docs_count, doc_fields_count, doc_offets, fields_info):
	docs_reader = io.BufferedReader(io.BytesIO(docs))

	for i in xrange(docs_count):
		print "current docs reader: ", docs_reader.tell()
		fields_count = doc_fields_count[i]
		doc = {}
		for j in xrange(fields_count):
			info_and_bits = read_vlong(docs_reader)
			field_number = info_and_bits >> 3 # bits required to store NUMERIC_DOUBLE 0x5
			field_info = fields_info[field_number]
			bits = info_and_bits & 7
			assert bits <= 0x5
			val = read_field(docs_reader, field_info, bits)
			doc[field_info["field_name"]] = val
		print "parse serialize doc: ", doc

# Field index allows the docs to be located within the uncompressed data
# https://lucene.apache.org/core/6_6_1/core/org/apache/lucene/codecs/compressing/CompressingStoredFieldsIndexWriter.html
def parse_field_index(f, offset, length):
	f.seek(offset)
	header_magic, name, version, object_id, suffix_length, generation = parse_header(f)
	print_header(header_magic, name, version, object_id, suffix_length, generation)

	packed_int_version = read_vint(f)
	print "packed_int_version: ", packed_int_version

	field_index = {}
	block_id = 0
	while True:
		num_chunks = read_vint(f)
		if num_chunks == 0:
			break
		doc_base = read_vint(f)
		avg_doc_per_chunk = read_vint(f)
		bits_per_doc_base = read_vint(f)

		print "number chunks: ", num_chunks
		print "doc base: ", doc_base
		print "average docs per chunk: ", avg_doc_per_chunk
		print "bits per doc base: ", bits_per_doc_base

		base_delta = pack64(f, num_chunks, bits_per_doc_base)
		print "docs base delta: ", base_delta

		start_pointer = read_vlong(f)
		avg_chunk_size = read_vlong(f)
		bits_per_start_pointer = read_vint(f)

		print "start pointer: ", start_pointer
		print "avg_chunk_size: ", avg_chunk_size
		print "bits_per_start_pointer: ", bits_per_start_pointer

		starter_delta = pack64(f, num_chunks, bits_per_start_pointer)
		print "start pointer delta: ", starter_delta

		field_index[block_id] = {"doc_base_delta": base_delta, "start_pointer_delta": starter_delta, "num_chunks": num_chunks, "doc_base": doc_base, "start_pointer": start_pointer}
		block_id += 1

	max_pointer = read_vlong(f)
	print "max pointer: ", max_pointer

	footer_magic, checksum_algo, checksum = parse_footer(f)
	actual_checksum = compute_checksum(f, offset, length)
	print_footer(footer_magic, checksum_algo, checksum, actual_checksum)
	return field_index, max_pointer

# https://lucene.apache.org/core/6_6_1/core/org/apache/lucene/codecs/lucene50/Lucene50StoredFieldsFormat.html
def parse_field_data(f, offset, d_length, max_pointer, field_index, fields_info):
	# getting footer information ahead of time
	f.seek(offset + max_pointer)
	print "max_pointer: ", offset + max_pointer
	num_chunks = read_vlong(f)
	num_dirty_chunks = read_vlong(f)
	# footer_magic, checksum_algo, checksum = parse_footer(f)

	f.seek(offset)
	header_magic, name, version, object_id, suffix_length, generation = parse_header(f)
	print_header(header_magic, name, version, object_id, suffix_length, generation)

	chunk_size = read_vint(f)
	packed_int_version = read_vint(f)
	print "chunks size: ", chunk_size
	print "packed_int_version: ", packed_int_version

	offsets_per_chunk = {}
	store_fields_chunk = {}
	start_ptr_chunk = {}
	data_per_chunk = {}
	for i in range(num_chunks):
		# Document ID 0 have offset of 0 wrt itself
		# Offset is where each document starts after metadata based on document ID
		offsets = {}
		offsets[0] = 0
		print "block {} start pointer {}".format(i, f.tell() - offset)

		chunk_doc_base = read_vint(f)
		token = read_vint(f)
		chunk_docs = token >> 1
		sliced = token & 1 != 0

		print "chunk doc base: ", chunk_doc_base
		print "chunk docs ", chunk_docs
		print "sliced: ", sliced
		if sliced:
			raise Exception("not implemented yet")

		if chunk_docs == 1:
			doc_fields_count = [read_vint(f)]
			doc_offsets = read_vint(f)
			offset[1] = doc_offsets
		else:
			bits_required = read_vint(f)
			if bits_required == 0:
				doc_fields_count = [read_vint(f)] * chunk_docs
			else:
				doc_fields_count = pack64(f, chunk_docs, bits_required)
			
			# parse length of each doc
			bits_per_doc_length = read_vint(f)
			if bits_per_doc_length == 0:
				length = read_vint(f)
				for j in xrange(chunk_docs):
					offsets[j + 1] = (1 + j) * length
			elif bits_per_doc_length > 31:
				raise Exception("bits length corrupted")
			else:
				offsets_diff = pack64(f, chunk_docs, bits_per_doc_length)
				for j in xrange(chunk_docs):
					offsets[j + 1] = offsets_diff[j] + offsets[j]

		start_ptr = f.tell()

		compressed_data_len = max_pointer + offset - start_ptr
		f.seek(start_ptr)

		print "doc fields count: ", doc_fields_count
		print "docs offsets: ", offsets
		print "chunk {} ptr {}".format(i, start_ptr)
		offsets_per_chunk[i] = offsets
		store_fields_chunk[i] = doc_fields_count
		start_ptr_chunk[i] = start_ptr

		data, d_length = decompress_lz4(f, offsets[chunk_docs])
		data_per_chunk[i] = data
		print "data: ", hexify(data), len(data)
		parse_serialize_docs(data, chunk_docs, doc_fields_count, offsets, fields_info)

	assert(offset + max_pointer == f.tell())
	num_chunks = read_vlong(f)
	num_dirty_chunks = read_vlong(f)
	footer_magic, checksum_algo, checksum = parse_footer(f)

	print "number chunks: {}, dirty chunks {}".format(num_chunks, num_dirty_chunks)
	print_footer(footer_magic, checksum_algo, checksum, "N/A")

def parse_post_writer_terms(f):
	# Note: it doesn't seem like the data following the data block is still been referenced, maybe deprecated?
	header_magic, name, version, object_id, suffix_length, generation = parse_header(f)
	print_header(header_magic, name, version, object_id, suffix_length, generation)

	index_block_size = read_vint(f)
	print "index_block_size: ", index_block_size

def get_bytes_reader(bytes_in):
	reader = io.BufferedReader(io.BytesIO(bytes_in))
	return reader

def parse_term_index_FST_block(f, offset, start_ptr, field):
	f_index_fd = os.dup(f.fileno())
	f_index = os.fdopen(f_index_fd, "rb")

	f_index.seek(offset + start_ptr)
	magic, codec, version = parse_header(f_index, suffix=False)
	version = intfy(version)
	print "FST block magic {}, codec {}, version {}".format(hexify(magic), codec, version)

	next_byte = f_index.read(1)

	packed = intfy(next_byte) == 1
	print "FST is packed: ", packed
	if intfy(f_index.read(1)) == 1:
		num_bytes = read_vint(f_index)
		empty_out = f_index.read(num_bytes)

		if packed:
			raise Exception("not implemented yet")
		else:
			output = hexify("".join(reversed(empty_out)))
			print "FST output for empty string ", output

	input_type = intfy(f_index.read(1))

	if input_type == 0:
		input_type_bytes = 1
	elif input_type == 1:
		input_type_bytes = 2
	elif input_type == 2:
		input_type_bytes = 4
	else:
		raise Exception("invalid input type received")

	start_node = read_vlong(f_index)
	if version < 5:
		raise Exception("doesn't handle anything that is older than current version")
	print "version: ", version

	# bytes array hold the structure of FST
	num_bytes = read_vlong(f_index)
	bytes_array = f_index.read(num_bytes)

	# since pack format is not supported, we will always read using reverse order
	fst_reader = get_bytes_reader("".join(reversed(bytes_array)))
	print "bytes array: len {}, data: {}".format(num_bytes, hexify(bytes_array))
	print "start node: ", start_node


def parse_posting_vint_block(f_doc, doc_delta_buffer, index_has_freq, left):
	if index_has_freq:
		for i in range(left):
			code = read_vint(f_doc)
			doc_delta_buffer[i] = code >> 1
			if code & 1:
				_freq = 1
			else:
				_freq = read_vint(f_doc)
	else:
		for i in range(left):
			doc_delta_buffer[i] = read_vint(f_doc)


def refill_docs(f_doc, doc_delta_buffer, index_has_freq, singleton_doc_id, left, doc_freq):
	assert left > 0
	if left > BLOCK_SIZE:
		# readBlock
		raise Exception("not implemented yet")
	elif doc_freq == 1:
		# special case
		doc_delta_buffer[0] = singleton_doc_id
	else:
		parse_posting_vint_block(f_doc, doc_delta_buffer, index_has_freq, left)

# This only simulate the blockDocsEnum
def parse_postings(f_doc, offset_doc, term_state, field_info):
	doc_ids = []
	index_opts = field_info["index_option_bits"]

	index_has_freq = index_opts >= INDEX_OPTION_DOCS_FREQS

	total_term_freq = term_state["total_term_freq"]
	doc_freq = term_state["doc_freq"]
	singleton_doc_id = term_state["singleton_doc_id"]
	if doc_freq > 1:
		# set the .doc position to the beginning of the block
		f_doc.seek(offset_doc + term_state["doc_start_fp"])

	doc = -1
	doc_up_to = 0
	buffer_up_to = BLOCK_SIZE
	accum = 0
	doc_delta_buffer = [0] * BLOCK_SIZE

	doc_ids = []
	while doc_up_to < doc_freq:
		if buffer_up_to == BLOCK_SIZE:
			refill_docs(f_doc, doc_delta_buffer, index_has_freq, singleton_doc_id, doc_freq - doc_up_to, doc_freq)
			buffer_up_to = 0
			
		accum += doc_delta_buffer[doc_up_to]
		doc_up_to += 1

		doc = accum
		buffer_up_to += 1

		doc_ids.append(accum)

	return doc_ids


def load_term_dict_block(f_dict, offset_dict, starting_fp, long_size, field_info, f_doc, offset_doc):
	index_opts = field_info["index_option_bits"]

	terms_fd = os.dup(f_dict.fileno())
	terms_in = os.fdopen(terms_fd, "rb")
	
	terms_in.seek(offset_dict + starting_fp)

	code = read_vint(terms_in)
	num_entries = code >> 1 # entries could either be number of terms or sub-block
	print "term block num_entries: ", num_entries

	is_last_floor = (code & 1) != 0
	print "term block is last floor: ", is_last_floor

	code = read_vint(terms_in)
	is_leaf_block = (code & 1) != 0
	num_bytes = code >> 1

	print "is leaf block ", is_leaf_block, num_bytes

	suffix_bytes = terms_in.read(num_bytes)
	num_bytes = read_vint(terms_in)
	stats_bytes = terms_in.read(num_bytes)
	num_bytes = read_vint(terms_in)
	metadata_bytes = terms_in.read(num_bytes)
	print "metadata_bytes: ", num_bytes, hexify(metadata_bytes)

	terms = {}
	suffix_reader = io.BufferedReader(io.BytesIO(suffix_bytes))
	stats_reader = io.BufferedReader(io.BytesIO(stats_bytes))
	metadata_reader = io.BufferedReader(io.BytesIO(metadata_bytes))

	field_has_position = index_opts >= INDEX_OPTION_DOCS_FREQS_POSITIONS
	field_has_offset = index_opts >= INDEX_OPTION_DOCS_FREQS_POSITIONS_OFFSETS

	doc_start_fp = 0
	pos_start_fp = 0
	payload_start_fp = 0
	for i in range(num_entries):
		suffix_length = read_vint(suffix_reader)
		suffix = suffix_reader.read(suffix_length)
		doc_freq = read_vint(stats_reader)

		if index_opts != INDEX_OPTION_DOCS:
			total_term_freq = doc_freq + read_vlong(stats_reader)
		else:
			# total term freq = doc_freq
			total_term_freq = doc_freq

		doc_start_fp += read_vlong(metadata_reader)
		if field_has_position:
			pos_start_fp += read_vlong(metadata_reader)
			if field_has_offset:
				# consume offset for payload (decodeTerm in Lucene50PostingsReader
				raise Exception("not supported yet")

		if doc_freq == 1:
			singleton_doc_id = read_vint(metadata_reader)
		else:
			singleton_doc_id = -1

		if field_has_position:
			if total_term_freq > BLOCK_SIZE:
				lastPosBlockOffset = read_vlong(metadata_reader)
			else:
				lastPosBlockOffset = -1

		if doc_freq > BLOCK_SIZE:
			skip_offset = read_vlong(metadata_reader)
		else:
			skip_offset = -1

		terms[i] = {"doc_freq": doc_freq, "doc_start_fp": doc_start_fp, "pos_start_fp": pos_start_fp, "payload_start_fp": payload_start_fp, "suffix": suffix,
		            "skip_offset": skip_offset, "total_term_freq": total_term_freq, "singleton_doc_id": singleton_doc_id}

		doc_ids = parse_postings(f_doc, offset_doc, terms[i], field_info)
		print "Term posting: field_name {}, term value: {}, doc_ids: {}".format(field_info["field_name"], terms[i]["suffix"], doc_ids)

	print "terms: ", terms
	fp_end = terms_in.tell()
	print "metadata bytes: ", hexify(metadata_bytes), fp_end


# f_dict: termsIn
def parse_term(f_dict, offset_dict, length_dict, fields_info, f_index, offset_index, length_index, f_doc, offset_doc):
	f_dict.seek(offset_dict)
	print "========================Terms dict header========================="
	header_magic, name, version, object_id, suffix_length, generation = parse_header(f_dict)
	print_header(header_magic, name, version, object_id, suffix_length, generation)
	parse_post_writer_terms(f_dict)

	print "========================Terms index header========================"
	f_index.seek(offset_index)
	header_magic, name, version, object_id, suffix_length, generation = parse_header(f_index)
	print_header(header_magic, name, version, object_id, suffix_length, generation)
	print "=================================================================="
	# set the pointer to the dirOffset which store the pointer to FieldSummary. 16 is the footer length and 8 is the long
	f_dict.seek(offset_dict + length_dict - 16 - 8)
	dir_offset = intfy(f_dict.read(8))
	
	# set the f_index to the dir_offset which store the pointer to the index start pointer
	f_index.seek(offset_index + length_index - 16 - 8)
	index_dir_offset = intfy(f_index.read(8))

	# get footer information
	footer_magic, checksum_algo, checksum = parse_footer(f_dict)

	f_dict.seek(offset_dict + dir_offset)
	num_fields = read_vint(f_dict)
	print "term_dict: number fields: ", num_fields

	f_index.seek(offset_index + index_dir_offset)

	fields = {}
	for i in xrange(num_fields):
		field_number = read_vint(f_dict)
		num_terms = read_vlong(f_dict)
		num_bytes = read_vint(f_dict)
		root_code = f_dict.read(num_bytes)
		field_info = fields_info[field_number]

		field_name = field_info["field_name"]
		fields[field_name] = {}


		index_opts = field_info["index_option_bits"]
		if index_opts == INDEX_OPTION_DOCS:
			sum_total_term_freq = -1
		else:
			sum_total_term_freq = read_vlong(f_dict)

		sum_doc_freq = read_vlong(f_dict)
		doc_count = read_vint(f_dict)
		longs_size = read_vint(f_dict)

		min_term = read_byteref(f_dict)
		max_term = read_byteref(f_dict)

		# index start ptr is relative
		index_start_ptr = read_vlong(f_index)
		fields[field_name]["num_terms"] = num_terms
		fields[field_name]["num_bytes"] = num_bytes
		fields[field_name]["root_code"] = hexify(root_code)
		fields[field_name]["index_opts"] = index_opts
		fields[field_name]["min_term"] = min_term
		fields[field_name]["max_term"] = max_term
		fields[field_name]["sum_doc_freq"] = sum_doc_freq
		fields[field_name]["doc_count"] = doc_count
		fields[field_name]["longs_size"] = longs_size
		fields[field_name]["index_start_ptr"] = index_start_ptr
		fields[field_name]["sum_total_term_freq"] = sum_total_term_freq

		root_code_f = io.BufferedReader(io.BytesIO(root_code))
		root_block_long = read_vlong(root_code_f)

		root_block_fp = root_block_long >> 2
		has_term = root_block_long & 0x2
		is_floor = root_block_long & 0x1


		fields[field_name]["root_block_fp"] = root_block_fp
		fields[field_name]["has_term"] = has_term
		fields[field_name]["is_floor"] = is_floor

		print "===============================Field Term==========================="
		print "parse term: Fields ", field_name, dir_offset, fields[field_name]
		parse_term_index_FST_block(f_index, offset_index, index_start_ptr, fields[field_name])
		load_term_dict_block(f_dict, offset_dict, root_block_fp, longs_size, field_info, f_doc, offset_doc)

	assert(f_dict.tell() == offset_dict + length_dict - 16 - 8)
	print_footer(footer_magic, checksum_algo, checksum, "N/A")

def parse_pos(f, offset, length):
	f.seek(offset)
	print "========================Posting Format========================="
	header_magic, name, version, object_id, suffix_length, generation = parse_header(f)
	print_header(header_magic, name, version, object_id, suffix_length, generation)
	
	f.seek(offset + length - 16)
	footer_magic, checksum_algo, checksum = parse_footer(f)
	print_footer(footer_magic, checksum_algo, checksum, "N/A")


def parse_payload(f, offset, length):
	f.seek(offset)
	print "========================payload Format========================="
	header_magic, name, version, object_id, suffix_length, generation = parse_header(f)
	print_header(header_magic, name, version, object_id, suffix_length, generation)
	
	f.seek(offset + length - 16)
	footer_magic, checksum_algo, checksum = parse_footer(f)
	print_footer(footer_magic, checksum_algo, checksum, "N/A")


def parse_doc(f, offset, length):
	f.seek(offset)
	print "========================Doc Format========================="
	header_magic, name, version, object_id, suffix_length, generation = parse_header(f)
	print_header(header_magic, name, version, object_id, suffix_length, generation)

	packed_int_version = read_vint(f)
	print "packed_int_version: ", packed_int_version

	formats = {}
	for i in range(1, 33):
		code = read_vint(f)
		format_id = code >> 5
		bits_per_value = code & 31 + 1
		formats[i] = {"format_id": format_id, "bits_per_value": bits_per_value, "code": code}

	print "formats: ", formats
	f.seek(offset + length - 16)
	footer_magic, checksum_algo, checksum = parse_footer(f)
	print_footer(footer_magic, checksum_algo, checksum, "N/A")

	return formats

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


def get_docs_with_field(field_entry_map, max_doc, f_doc_data, f_doc_offset):
	# Needs to implemented it next
	for _field, _data in field_entry_map.items():
		field_info = _data["info"]
		doc_values_type = field_info["field_type"]

		if doc_values_type == DOC_VALUES_SORTED_SET:
			sorted_set = get_sorted_set(_data, f_doc_data, f_doc_offset)
			print "_field: {}, doc_values {}".format(_field, sorted_set)
		elif doc_values_type == DOC_VALUES_SORTED_NUMERIC:
			pass
		elif doc_values_type == DOC_VALUES_SORTED:
			pass
		elif doc_values_type == DOC_VALUES_BINARY:
			pass
		elif doc_values_type == DOC_VALUES_NUMERIC:
			entry = _data["numeric"]
			if entry["format"] == DOC_SPARSE_COMPRESSED:
				raise Exception("todo: not implemented")
			else:
				live_bits = get_live_bits(entry["missing_offset"], max_doc)
				live_bits["constant"] = entry["min_value"]
				print "_field {}, doc_values {}".format(_field, live_bits)
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
		return {"reader": bin_reader, "length": entry["max_length"], "binary_blob": bin_blob}

	elif _format == DOC_BINARY_VARIABLE_UNCOMPRESSED:
		raise Exception("todo: needs to implement")
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
			return {"constant": constant, "format": "ALL_LIVE"}
		elif missing_offset == 0xfffffffffffffffe:
			# all missing, always return False
			return {"constant": 0, "format": "ALL_MISSING"}
		else:
			# random sliced the data
			length = (count + 7) >> 3
			f_doc_data.seek(f_doc_offset + missing_offset)
			live_data = f_doc_data.read(length)
			live_reader = io.BufferedReader(io.BytesIO(live_data))
			return {"live_reader": live_reader, "constant": constant}

	elif _format == DOC_DELTA_COMPRESSED:
		# set the file pointer
		f_doc_data.seek(f_doc_offset + entry["offset"])
		length = entry["end_offset"] - entry["offset"]
		numeric_blob = f_doc_data.read(length)
		numeric_reader = io.BufferedReader(io.BytesIO(numeric_blob))
		delta = entry["min_value"]

		bits_per_value = entry["bits_per_value"]
		if bits_per_value != 1:
			raise Exception("todo: needs to implemented")

		return {"delta": delta, "bits_per_value": bits_per_value, "numeric_reader": numeric_reader, "numeric_blob": numeric_blob}

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
	

def get_sorted_numeric(entries):
	pass

def get_sorted_set(entries, f_doc_data, f_doc_offset):
	entry = entries["ss"]
	_format = entry["format"]
	if _format == DOC_SORTED_SINGLE_VALUED:
		sorted_doc_values = get_sorted(entries, f_doc_data, f_doc_offset)
		return sorted_doc_values
	elif _format == DOC_SORTED_WITH_ADDRESSES:
		pass
	elif _format == DOC_SORTED_SET_TABLE:
		pass
	else:
		raise Exception("invalid doc value format")


def parse_doc_values(f, doc_val_meta_off, doc_val_meta_length, doc_val_data_off, doc_val_data_length, fields_info, segment_size):
	f_meta_fd = os.dup(f.fileno())
	f_meta = os.fdopen(f_meta_fd, "rb")

	f_data_fd = os.dup(f.fileno())
	f_data = os.fdopen(f_data_fd, "rb")

	f_meta.seek(doc_val_meta_off)
	header_magic, name, version, object_id, suffix_length, generation = parse_header(f_meta)
	print_header(header_magic, name, version, object_id, suffix_length, generation)

	number_fields = 0
	field_entry_map = {}
	while True:
		field_number = read_vint(f_meta)
		# how to represent -1 in vint?
		if field_number == -1 or field_number == 0xffffffff:
			break

		number_fields += 1
		info = fields_info[field_number]

		field_type = intfy(f_meta.read(1))
		# print "field_type: ", field_type
		info["field_type"] = field_type
		if field_type == DOC_VALUES_NUMERIC:
			entry = read_numeric_entry(f_meta, info, segment_size)
			field_entry_map[info["field_name"]] = {"numeric": entry, "info": info}
		elif field_type == DOC_VALUES_BINARY:
			entry = read_binary_entry(f_meta, info)
			field_entry_map[info["field_name"]] = {"binary": entry, "info": info}
		elif field_type == DOC_VALUES_SORTED:
			binary_entry, ord_entry = read_sorted_entry(f_meta, info, segment_size)
			field_entry_map[info["field_name"]] = {"binary": binary_entry, "ord": ord_entry, "info": info}
		elif field_type == DOC_VALUES_SORTED_SET:
			ss_entry = read_sorted_set_entry(f_meta, info)
			# field_entry_map[info["field_name"]] = ss_entry
			# print "ss_entry: ", ss_entry
			if ss_entry["format"] == DOC_SORTED_WITH_ADDRESSES:
				binary_entry, ord_entry, ord_index_entry = read_sorted_set_field_with_addr(f_meta, info)
				field_entry_map[info["field_name"]] = {"binary": binary_entry, "ord": ord_entry, "ord_index": ord_index_entry, "ss": ss_entry, "info": info}
			elif ss_entry["format"] == DOC_SORTED_SET_TABLE:
				# make sure add ss_entry to field entry map
				binary_entry, ord_entry = read_sorted_set_field_with_table(f_meta, info)
				field_entry_map[info["field_name"]] = {"binary": binary_entry, "ord": ord_entry, "ss": ss_entry, "info": info}
			elif ss_entry["format"] == DOC_SORTED_SINGLE_VALUED:
				if read_vint(f_meta) != info["field_number"]:
					raise Exception("corrupted field number")

				_format = intfy(f_meta.read(1))
				if _format != DOC_VALUES_SORTED:
					raise Exception("corrupted doc value type {}".format(_format))
				
				binary_entry, ord_entry = read_sorted_entry(f_meta, info, segment_size)
				field_entry_map[info["field_name"]] = {"binary": binary_entry, "ord": ord_entry, "ss": ss_entry, "info": info}
			else:
				raise Exception("unkown format")

		elif field_type == DOC_VALUES_SORTED_NUMERIC:
			ss_entry = read_sorted_set_entry(f_meta, info)
			if ss_entry["format"] == DOC_SORTED_WITH_ADDRESSES:
				if read_vint(f_meta) != info["field_number"]:
					raise Exception("data corrupted")
				if read_byte(f_meta) != DOC_VALUES_NUMERIC:
					raise Exception("data corrupted")

				numeric_entry = read_numeric_entry(f_meta, info)

				if read_vint(f_meta) != info["field_number"]:
					raise Exception("data corrupted")
				if read_byte(f_meta) != DOC_VALUES_NUMERIC:
					raise Exception("data corrupted")

				ord_index_entry = read_numeric_entry(f_meta, info)

				field_entry_map[info["field_name"]] = {"numeric": numeric_entry, "ord_index": ord_index_entry, "ss": ss_entry, "info": info}
				
			elif ss_entry["format"] == DOC_SORTED_SET_TABLE:
				if read_vint(f_meta) != info["field_number"]:
					raise Exception("data corrupted")
				if read_byte(f_meta) != DOC_VALUES_NUMERIC:
					raise Exception("data corrupted")

				ord_entry = read_numeric_entry(f_meta, info)
				field_entry_map[info["field_name"]] = {"ord": ord_entry, "ss": ss_entry, "info": info}
			elif ss_entry["format"] == DOC_SORTED_SINGLE_VALUED:
				if read_vint(f_meta) != info["field_number"]:
					raise Exception("data corrupted")
				if read_byte(f_meta) != DOC_VALUES_NUMERIC:
					raise Exception("data corrupted")

				numeric_entry = read_numeric_entry(f_meta, info)
				field_entry_map[info["field_name"]] = {"numeric": numeric_entry, "ss": ss_entry, "info": info}
			else:
				raise Exception("corrupted exception")
		else:
			raise Exception("Unknown field type")

	print "number_fields visited: ", number_fields
	print "field_entry_map: ", field_entry_map

	print "\n\n+++++++++++++++++++doc values data+++++++++++++++++++"
	f_data.seek(doc_val_data_off)
	header_magic, name, version, object_id, suffix_length, generation = parse_header(f_data)
	print_header(header_magic, name, version, object_id, suffix_length, generation)

	get_docs_with_field(field_entry_map, segment_size, f_data, doc_val_data_off)
	return field_entry_map, number_fields

def read_norms_fields_meta(f_meta, fields_info):
	norms_fields_meta = {}
	while True:
		field_number = read_vint(f_meta)
		if field_number == 0xffffffff:
			break

		info = fields_info[field_number]
		if not(info["index_option_bits"] != INDEX_OPTION_NONE and info["omit_norm"] == False):
			raise Exception("corrupted field types")

		entry = {}
		entry["bytes_per_value"] = read_byte(f_meta)
		entry["offset"] = read_long(f_meta)
		norms_fields_meta[field_number] = entry

	return norms_fields_meta

def read_norms(f_data, norms_fields_meta):
	for field_id, norm_entry in norms_fields_meta.items():
		if norm_entry["bytes_per_value"] == 0:
			print "norm field id {}, value {}".format(field_id, norm_entry["offset"])
		else:
			raise Exception("todo: needs to implement")


def parse_norms(f, norm_meta_off, norm_meta_len, norm_data_off, norm_data_len, fields_info):
	f_meta_fd = os.dup(f.fileno())
	f_meta = os.fdopen(f_meta_fd, "rb")

	f_data_fd = os.dup(f.fileno())
	f_data = os.fdopen(f_data_fd, "rb")

	f_meta.seek(norm_meta_off)
	header_magic, name, version, object_id, suffix_length, generation = parse_header(f_meta)
	print_header(header_magic, name, version, object_id, suffix_length, generation)

	norm_fields = read_norms_fields_meta(f_meta, fields_info)
	print "parse norms fields metadata: ", norm_fields

	read_norms(f_data, norm_fields)


def parse_cfs(_file, file_map, segment_size):
	with open(_file + ".cfs", "rb") as f:
		yield parse_header(f)

		# AKA field_info
		fields_info = parse_fields(f, file_map[".fnm"]["offset"], file_map[".fnm"]["length"])
		yield fields_info

		# AKA Lucene50PostingsFormat
		docs = parse_doc(f, file_map["_Lucene50_0.doc"]["offset"], file_map["_Lucene50_0.doc"]["length"])
		yield docs

		pos = parse_pos(f, file_map["_Lucene50_0.pos"]["offset"], file_map["_Lucene50_0.pos"]["length"])
		yield pos

		# this is optional, depends if any of the field requires the payload
		# payload = parse_payload(f, file_map["_Lucene50_0.pay"]["offset"], file_map["_Lucene50_0.pay"]["length"])
		# yield payload

		# AKA storedFieldsFormat.FieldsReader, fdx, fdt contains the raw document stored in compressed way
		field_index, max_pointer = parse_field_index(f, file_map[".fdx"]["offset"], file_map[".fdx"]["length"])
		yield field_index, max_pointer
		yield parse_field_data(f, file_map[".fdt"]["offset"], file_map[".fdt"]["length"], max_pointer, field_index, fields_info)

		# AKA Terms, responsible for inverted-mapping
		f_index_fd = os.dup(f.fileno())
		f_index = os.fdopen(f_index_fd, "rb")

		f_doc_fd = os.dup(f.fileno())
		f_doc = os.fdopen(f_doc_fd, "rb")
		yield parse_term(f, file_map["_Lucene50_0.tim"]["offset"], file_map["_Lucene50_0.tim"]["length"], fields_info, f_index,
			                file_map["_Lucene50_0.tip"]["offset"], file_map["_Lucene50_0.tip"]["length"],
			                f_doc, file_map["_Lucene50_0.doc"]["offset"])

		yield parse_doc_values(f, file_map["_Lucene54_0.dvm"]["offset"], file_map["_Lucene54_0.dvm"]["length"],
			                file_map["_Lucene54_0.dvd"]["offset"], file_map["_Lucene54_0.dvd"]["length"],
			                fields_info, segment_size)

		yield parse_norms(f, file_map[".nvm"]["offset"], file_map[".nvm"]["length"],
			                 file_map[".nvd"]["offset"], file_map[".nvd"]["length"],
			                 fields_info)


def read_segment(_file):
	segment_iter = parse_segment(_file)

	# gneeration id should match the segment file suffix
	header_magic, name, version, object_id, suffix_length, generation = segment_iter.next()
	print_header(header_magic, name, version, object_id, suffix_length, generation)

	print "Lucene major {}, minor {}, bug {}".format(*segment_iter.next())
	print "index ops count: ", segment_iter.next()
	print "name_counter: ", segment_iter.next()
	num_segments = segment_iter.next()
	print "segment count: ", num_segments
	print "Lucene Min segments version: major {}, minor {}, bug {}".format(*segment_iter.next())
	for i in range(num_segments):
		print "segment info ", segment_iter.next()

	print "User data: ", segment_iter.next()

	footer_magic, checksum_algo, checksum = segment_iter.next()
	print_footer(footer_magic, checksum_algo, checksum, segment_iter.next())


def read_segment_info(_file):
	segment_info_iter = parse_segment_info(_file)
	header_magic, name, version, object_id, suffix_length, generation = segment_info_iter.next()
	print_header(header_magic, name, version, object_id, suffix_length, generation)
	print "Lucene major {}, minor {}, bug {}".format(*segment_info_iter.next())
	segment_size = segment_info_iter.next()

	print "segment size: ", segment_size
	print "is compound file: ", segment_info_iter.next()
	print "diagnostics: ", segment_info_iter.next()
	print "files set: ", segment_info_iter.next()
	print "attributes: ", segment_info_iter.next()

	# Elasticsearch is not using the sort field features(maybe because it expect every docuemnt to have such a field)
	# it is new feature in ES 6
	print "num_sort_fields: ", segment_info_iter.next()

	footer_magic, checksum_algo, checksum = segment_info_iter.next()
	print_footer(footer_magic, checksum_algo, checksum, segment_info_iter.next())

	# maxDoc is the segment size
	return segment_size


def read_compound_file(_file, segment_size):
	cfe_iter = parse_cfe(_file)
	header_magic, name, version, object_id, suffix_length, generation = cfe_iter.next()
	print "compound file entry header:"
	print_header(header_magic, name, version, object_id, suffix_length, generation)

	num_files = cfe_iter.next()
	print "number of files: ", num_files

	file_map = cfe_iter.next()
	print "compound entries: ", file_map

	print "\n\n\ncompound file system"
	cfs_iter = parse_cfs(_file, file_map, segment_size)
	header_magic, name, version, object_id, suffix_length, generation = cfs_iter.next()
	print_header(header_magic, name, version, object_id, suffix_length, generation)

	print "\n\n\nfield info format"
	cfs_iter.next()

	print "\n\ndoc posting"
	cfs_iter.next()

	print "\n\nposition"
	cfs_iter.next()

	# print "\n\npayload"
	# cfs_iter.next()

	print "\n\n\n++++++++++++++++++++++field index+++++++++++++++++"
	cfs_iter.next()

	print "\n\n\n++++++++++++++++++++++field data++++++++++++++++++"
	cfs_iter.next()

	print "\n\n\n+++++++++++++++++++++++terms++++++++++++++++++++++"
	cfs_iter.next()

	print "\n\n\n+++++++++++++++++++++++doc values++++++++++++++++++++++"
	cfs_iter.next()

	print "\n\n\n++++++++++++++++++++++norms+++++++++++++++++++++++++"
	cfs_iter.next()


if __name__ == "__main__":
	_file = "./sample_index/index/segments_3"
	read_segment(_file)
	print "\n\n\n###########################################"
	# Print segment info
	_segment_info = "./sample_index/index/_e.si"
	segment_size = read_segment_info(_segment_info)

	print "\n\n\n###########################################"
	read_compound_file("./sample_index/index/_e", segment_size)


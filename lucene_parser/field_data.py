from .file_reader import FileReader
from .pack64 import Pack64
from .utils import *

class FieldData(FileReader):
	extension = ".fdt"

	def __init__(self, segment_info, field_index, field_infos):
		self.field_index = field_index
		self.field_infos = field_infos
		super(FieldData, self).__init__(segment_info)
		self.f = self.get_file_ptr()

	def parse_field_data(self):
		print("#######################################################")
		print("###################### FIELD DATA #####################")
		print("#######################################################")

		max_pointer = self.field_index.max_pointer
		offset = self.offset
		f = self.f

		f.seek(offset)
		print_header(*parse_header(f))

		chunk_size = read_vint(f)
		packed_int_version = read_vint(f)
		print("chunk_size {}, packed_int_version {}".format(chunk_size, packed_int_version))


		# offsets_per_chunk = {}
		# store_fields_chunk = {}
		# start_ptr_chunk = {}
		# data_per_chunk = {}

		# for i in range(num_chunks):
		# 	print("chunk {} start pointer {}".format(i, f.tell() - offset))

		# 	# Document ID 0 have offset of 0 wrt itself
		# 	# Offset is where each document starts after metadata based on document ID
		# 	offsets = {}
		# 	offsets[0] = 0
		# 	chunk_doc_base = read_vint(f)
		# 	token = read_vint(f)
		# 	chunk_docs = token >> 1
		# 	sliced = token & 1 != 0

		# 	if sliced:
		# 		raise Exception("not implemented yet")

		# 	if chunk_docs == 1:
		# 		doc_fields_count = [read_vint(f)]
		# 		doc_offsets = read_vint(f)
		# 		offsets[1] = doc_offsets
		# 	else:
		# 		bits_required = read_vint(f)
		# 		if bits_required == 0:
		# 			doc_fields_count = [read_vint(f)] * chunk_docs
		# 		else:
		# 			doc_fields_count = Pack64(f, chunk_docs, bits_required)
				
		# 		# parse length of each doc
		# 		bits_per_doc_length = read_vint(f)
		# 		if bits_per_doc_length == 0:
		# 			length = read_vint(f)
		# 			for j in xrange(chunk_docs):
		# 				offsets[j + 1] = (1 + j) * length
		# 		elif bits_per_doc_length > 31:
		# 			raise Exception("bits length corrupted")
		# 		else:
		# 			# offsets_diff = pack64(f, chunk_docs, bits_per_doc_length)
		# 			offsets_diff = Pack64(f, chunk_docs, bits_per_doc_length)
		# 			print(offsets_diff)
		# 			print(bits_per_doc_length * chunk_docs)
		# 			for j in range(chunk_docs):
		# 				diff = offsets_diff[j]
		# 				offsets[j + 1] = diff + offsets[j]

		# 	start_ptr = f.tell()
		# 	f.seek(start_ptr)

		# 	offsets_per_chunk[i] = offsets
		# 	store_fields_chunk[i] = doc_fields_count
		# 	start_ptr_chunk[i] = start_ptr

		# 	data, d_length = decompress_lz4(f, offsets[chunk_docs])
		# 	data_per_chunk[i] = data
		# 	parse_serialize_docs(data, chunk_docs, doc_fields_count, offsets, self.field_infos, chunk_doc_base)

		# assert(offset + max_pointer == f.tell())

		f.seek(offset + max_pointer)
		num_chunks = read_vlong(f)
		num_dirty_chunks = read_vlong(f)
		print("num_chunks: {}, num_dirty_chunks {}".format(num_chunks, num_dirty_chunks))

		footer_magic, checksum_algo, checksum = parse_footer(f)
		actual_checksum = compute_checksum(f, self.offset, self.length)
		print_footer(footer_magic, checksum_algo, checksum, actual_checksum)

	def __iter__(self):
		for block_id, num_chunks in self.field_index:
			for chunk_id in range(num_chunks):
				yield self.parse_chunk(block_id, chunk_id)

	def parse_serialize_docs(self, data, docs_count, doc_fields_count, doc_offets, fields_info, doc_base):
		docs_reader = io.BufferedReader(io.BytesIO(data))
		docs = []
		for i in range(docs_count):
			doc = {}
			doc["doc_id"] = doc_base + i
			doc["doc_start_ptr"] = docs_reader.tell()
			fields_count = doc_fields_count[i]
			
			for j in range(fields_count):
				info_and_bits = read_vlong(docs_reader)
				field_number = info_and_bits >> 3 # bits required to store NUMERIC_DOUBLE 0x5
				field_info = fields_info[field_number]
				bits = info_and_bits & 7
				assert bits <= 0x5
				val = read_field(docs_reader, field_info, bits)
				field_name = field_info["field_name"]
				doc[field_name] = str(val)

			docs.append(doc)

		return docs

	def parse_chunk(self, block_id, chunk_id):
		f = self.f
		offset = self.offset
		start_pointer = self.field_index.get_chunk_start_ptr(block_id, chunk_id)
		f.seek(offset + start_pointer)

		print("parse block {}, chunk: {} start pointer {}".format(block_id, chunk_id, start_pointer))
		# Document ID 0 have offset of 0 wrt itself
		# Offset is where each document starts after metadata based on document ID
		offsets = {}
		offsets[0] = 0
		chunk_doc_base = read_vint(f)
		token = read_vint(f)
		chunk_docs = token >> 1
		sliced = token & 1 != 0

		if sliced:
			raise Exception("not implemented yet")

		if chunk_docs == 1:
			doc_fields_count = [read_vint(f)]
			doc_offsets = read_vint(f)
			offsets[1] = doc_offsets
		else:
			bits_required = read_vint(f)
			if bits_required == 0:
				doc_fields_count = [read_vint(f)] * chunk_docs
			else:
				doc_fields_count = Pack64(f, chunk_docs, bits_required)
			
			# parse length of each doc
			bits_per_doc_length = read_vint(f)
			if bits_per_doc_length == 0:
				length = read_vint(f)
				for j in range(chunk_docs):
					offsets[j + 1] = (1 + j) * length
			elif bits_per_doc_length > 31:
				raise Exception("bits length corrupted")
			else:
				# offsets_diff = pack64(f, chunk_docs, bits_per_doc_length)
				offsets_diff = Pack64(f, chunk_docs, bits_per_doc_length)
				for j in range(chunk_docs):
					diff = offsets_diff[j]
					offsets[j + 1] = diff + offsets[j]

		data, d_length = decompress_lz4(f, offsets[chunk_docs])
		docs = self.parse_serialize_docs(data, chunk_docs, doc_fields_count, offsets, self.field_infos, chunk_doc_base)
		return docs
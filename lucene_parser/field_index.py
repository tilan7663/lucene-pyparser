import json

from .direct_8 import Direct_8
from .file_reader import FileReader	
from .pack64 import Pack64
from .utils import *

class FieldIndex(FileReader):
	extension = ".fdx"

	def __init__(self, segment_info):
		super(FieldIndex, self).__init__(segment_info)
		self.f = self.get_file_ptr()

	def parse_field_index(self):
		print("#######################################################")
		print("###################### FIELD INDEX ####################")
		print("#######################################################")

		f = self.f
		f.seek(self.offset)
		print_header(*parse_header(f))

		packed_int_version = read_vint(f)
		print("packed_int_version: {}".format(packed_int_version))

		field_index = {}
		block_id = 0

		while True:
			num_chunks = read_vint(f)
			if num_chunks == 0:
				break

			print("num_chunks {}".format(num_chunks))
			doc_base = read_vint(f)
			avg_doc_per_chunk = read_vint(f)
			bits_per_doc_base = read_vint(f)
			base_delta = Pack64(f, num_chunks, bits_per_doc_base, signed=True)
			start_pointer = read_vlong(f)
			avg_chunk_size = read_vlong(f)
			bits_per_start_pointer = read_vint(f)
			starter_delta = Pack64(f, num_chunks, bits_per_start_pointer, signed=True)
			# starter_delta = Direct_8(f, num_chunks)

			field_index[block_id] = {"doc_base_delta": base_delta,
									 "start_pointer_delta": starter_delta,
									 "num_chunks": num_chunks,
									 "doc_base": doc_base,
									 "start_pointer": start_pointer,
									 "avg_chunk_size": avg_chunk_size,
									 "avg_doc_per_chunk": avg_doc_per_chunk}
			block_id += 1

		print("block start pointer {}".format(start_pointer))
		self.max_pointer = read_vlong(f)
		self.field_index = field_index

		print(field_index)

		footer_magic, checksum_algo, checksum = parse_footer(f)
		actual_checksum = compute_checksum(f, self.offset, self.length)
		print_footer(footer_magic, checksum_algo, checksum, actual_checksum)

	def get_chunk_start_ptr(self, block_id, chunk_id):
		start_pointer = self.field_index[block_id]["start_pointer"]
		avg_chunk_size = self.field_index[block_id]["avg_chunk_size"]
		start_pointer_delta = self.field_index[block_id]["start_pointer_delta"][chunk_id]

		return start_pointer + avg_chunk_size * chunk_id + zigzag_decode(start_pointer_delta)

	def get_doc_base(self, block_id, chunk_id):
		doc_base = self.field_index[block_id]["doc_base"]
		avg_chunk_docs = self.field_index[block_id]["avg_doc_per_chunk"]
		doc_base_delta = self.field_index[block_id]["doc_base_delta"][chunk_id]
		return doc_base + avg_chunk_docs * chunk_id + zigzag_decode(doc_base_delta)

	def __str__(self):
		field_index_ptr = {}
		for block_id, block in self.field_index.items():
			num_chunks = block["num_chunks"]
			chunk_ptr = {}
			for _id in range(num_chunks):
				doc_base = self.get_doc_base(block_id, _id)
				start_pointer = self.get_chunk_start_ptr(block_id, _id)
				chunk_ptr[_id] = {"start_pointer": start_pointer, "doc_base": doc_base}

			field_index_ptr[block_id] = chunk_ptr

		return json.dumps(field_index_ptr, sort_keys=False, indent=4)

	def __iter__(self):
		for block_id, block in self.field_index.items():
			num_chunks = block["num_chunks"]
			yield block_id, num_chunks

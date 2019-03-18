import json
import os

from .constants import *
from .file_reader import FileReader	
from .utils import *

class FieldInfos(FileReader):
	extension = ".fnm"

	def __init__(self, segment_info):
		super(FieldInfos, self).__init__(segment_info)
		self.f = self.get_file_ptr()

	def parse_field_info(self):
		print("#######################################################")
		print("###################### FIELD INFO #####################")
		print("#######################################################")

		f = self.f
		f.seek(self.offset)

		print_header(*parse_header(f))
		self.fields_count = read_vint(f)

		fields = {}
		for i in range(self.fields_count):
			field_name = read_string(f)
			field_number = read_vint(f)
			field_bits = read_byte(f)
			store_term_vec = field_bits & STORE_TERMVECTOR != 0
			omit_norm = field_bits & OMIT_NORMS != 0
			store_payload = field_bits & STORE_PAYLOADS != 0
			index_option_bits = read_byte(f)
			doc_values_bits = read_byte(f)
			doc_values_gen = hex(read_long(f))
			attributes = read_string_map(f)
			dimension_count = read_vint(f)
			if dimension_count != 0:
				dimension_member_bytes = read_vint(f)
			else:
				dimension_member_bytes = 0

			fields[field_number] = {
				"field_name": field_name,
				"field_number": field_number,
				"field_bits": field_bits,
				"index_option_bits": index_option_bits,
				"doc_values_bits": doc_values_bits,
				"doc_values_gen": doc_values_gen,
				"attributes": attributes,
				"dimension_count": dimension_count,
				"store_term_vec": store_term_vec,
				"omit_norm": omit_norm,
				"store_payload": store_payload,
				"dimension_member_bytes": dimension_member_bytes
			}

		self.fields = fields
		footer_magic, checksum_algo, checksum = parse_footer(f)
		actual_checksum = compute_checksum(f, self.offset, self.length)
		print_footer(footer_magic, checksum_algo, checksum, actual_checksum)

	def has_prox(self):
		for _, field in self.fields.items():
			index_option_bits = field["index_option_bits"]
			if index_option_bits >= INDEX_OPTION_DOCS_FREQS_POSITIONS:
				return True

		return False

	def has_offsets(self):
		for _, field in self.fields.items():
			index_option_bits = field["index_option_bits"]
			if index_option_bits >= INDEX_OPTION_DOCS_FREQS_POSITIONS_OFFSETS:
				return True

		return False

	def has_payloads(self):
		for _, field in self.fields.items():
			store_payload = field["store_payload"]
			if store_payload:
				return True

		return False

	def __str__(self):
		return json.dumps(self.fields, sort_keys=False, indent=4)

	def __getitem__(self, field_num):
		return self.fields[field_num]

	def __iter__(self):
		for field_name, field_info in self.fields.items():
			yield field_name, field_info
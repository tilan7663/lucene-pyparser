import json

from .file_reader import FileReader	
from .utils import *


class NormMeta(FileReader):
	extension = ".nvm"
	def __init__(self, segment_info, field_infos):
		super(NormMeta, self).__init__(segment_info)
		self.f = self.get_file_ptr()
		self.field_infos = field_infos

	def parse_norm_meta(self):
		print("#######################################################")
		print("###################### NORM META ######################")
		print("#######################################################")

		field_infos = self.field_infos
		f = self.f
		f.seek(self.offset)
		print_header(*parse_header(f))

		norms_fields_meta = {}

		while True:
			field_number = read_vint(f)
			if field_number == 0xffffffff:
				break

			info = field_infos[field_number]
			if not(info["index_option_bits"] != INDEX_OPTION_NONE and info["omit_norm"] == False):
				raise Exception("corrupted field types")

			entry = {}
			entry["bytes_per_value"] = read_byte(f)
			entry["offset"] = read_long(f)
			entry["field_name"] = info["field_name"]
			norms_fields_meta[field_number] = entry

		footer_magic, checksum_algo, checksum = parse_footer(f)
		actual_checksum = compute_checksum(f)
		print_footer(footer_magic, checksum_algo, checksum, actual_checksum)

		self.norms_fields_meta = norms_fields_meta

	def __iter__(self):
		for field_number, entry in self.norms_fields_meta.items():
			yield field_number, entry

	def __str__(self):
		return json.dumps(self.norms_fields_meta, sort_keys=False, indent=4)
import json
import os

from .utils import *

class SegmentInfo(object):
	extension = ".si"

	def __init__(self, segment_path, name, metadata):
		self.base_path = segment_path
		self.name = name
		self.segment_file = name + self.extension
		self.metadata = metadata
		self.file_map = {}

	def load(self):
		self.load_segment_info()
		self.parse_cfe()

	def load_segment_info(self):
		print("#######################################################")
		print("#################### SEGMENT INFO #####################")
		print("#######################################################")

		segment_info_path = os.path.join(self.base_path, self.segment_file)
		with open(segment_info_path, "rb") as f:
			print_header(*parse_header(f))

			major, minor, bug = parse_segment_info_version(f)
			print("Lucene major {}, minor {}, bug {}".format(major, minor, bug))

			self.segment_size = read_int(f)
			is_compound_file = read_byte(f)

			if is_compound_file == 0xff:
				self.is_compound_file = False
			else:
				self.is_compound_file = True

			self.diagnostics = read_string_map(f)
			self.set_files = read_string_set(f)
			self.attributes = read_string_map(f)
			self.num_sort_fields = read_vint(f)

			if self.num_sort_fields > 0:
				raise Exception("Not implemented yet")

			print("segment_size: {}".format(self.segment_size))
			print("is_compound_file: {}".format(self.is_compound_file))
			print("diagnostics: {}".format(self.diagnostics))
			print("set_files: {}".format(self.set_files))
			print("attributes: {}".format(self.attributes))
			print("num_sort_fields: {}".format(self.num_sort_fields))

			footer_magic, checksum_algo, checksum = parse_footer(f)
			actual_checksum = compute_checksum(f)
			print_footer(footer_magic, checksum_algo, checksum, actual_checksum)

	def parse_cfe(self):
		if not self.is_compound_file:
			return

		segment_cfe_path = os.path.join(self.base_path, self.name + ".cfe")
		with open(segment_cfe_path, "rb") as f:
			print_header(*parse_header(f))
			num_files = read_vint(f)
			for i in xrange(num_files):
				file_name =  read_string(f)
				data_offset = read_long(8)
				data_length = read_long(8)
				self.file_map[file_name] = {"offset": data_offset, "length": data_length}

	def __str__(self):
		return json.dumps(self.metadata)

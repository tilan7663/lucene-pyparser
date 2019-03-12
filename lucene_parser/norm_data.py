import json

from .file_reader import FileReader	
from .utils import *


class NormData(FileReader):
	extension = ".nvd"
	def __init__(self, segment_info, norm_meta):
		super(NormData, self).__init__(segment_info)
		self.norm_meta = norm_meta
		self.f = self.get_file_ptr()

	def parse_norm_data(self):
		print("#######################################################")
		print("###################### NORM DATA ######################")
		print("#######################################################")

		segment_size = self.segment_info.segment_size
		norm_meta = self.norm_meta
		f = self.f
		norm_data = {}

		f.seek(self.offset)
		print_header(*parse_header(f))
		for field_number, entry in norm_meta:
			print("norm data: field {}, ptr {}".format(entry["field_name"], f.tell()))

			field_offset = entry["offset"]
			bytes_per_value = entry["bytes_per_value"]
			norm_values = {}

			f.seek(self.offset + field_offset)

			for i in range(segment_size):
				value = intfy(f.read(bytes_per_value))
				norm_values[i] = value

			norm_data[field_number] = norm_values

		self.norm_data = norm_data

	def read_norm_value(field_num, doc_id):
		meta = self.norm_meta[field_num]
		f = self.f
		offset = meta["offset"]
		bytes_per_value = meta["bytes_per_value"]
		index = doc_id * bytes_per_value
		f.seek(self.offset + offset + index)
		return intfy(f.read(bytes_per_value))

	def __iter__(self):
		for field_number, norm_values in self.norm_data.items():
			for doc_id, value in norm_values.items():
				yield doc_id, value

	def __str__(self):
		return json.dumps(self.norm_data, sort_keys=False, indent=4)
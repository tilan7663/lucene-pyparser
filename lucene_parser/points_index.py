import json

from .file_reader import FileReader	
from .utils import *


class PointsIndex(FileReader):
	extension = ".dii"
	def __init__(self, segment_info, field_infos):
		super(PointsIndex, self).__init__(segment_info)
		self.f = self.get_file_ptr()
		self.field_infos = field_infos

	def parse_points_index(self):
		print("#######################################################")
		print("##################### POINTS INDEX ####################")
		print("#######################################################")
		f = self.f
		field_infos =  self.field_infos
		points_index = {}

		f.seek(self.offset)
		print_header(*parse_header(f))

		field_count = read_vint(f)

		for i in range(field_count):
			field_number = read_vint(f)
			fp = read_vint(f)
			points_index[field_number] = {"offset": fp, "field_name": field_infos[field_number]["field_name"]}

		self.points_index = points_index

		footer_magic, checksum_algo, checksum = parse_footer(f)
		actual_checksum = compute_checksum(f)
		print_footer(footer_magic, checksum_algo, checksum, actual_checksum)

	def __str__(self):
		return json.dumps(self.points_index, sort_keys=False, indent=4)

	def __iter__(self):
		for field_number, entry in self.points_index.items():
			yield field_number, entry
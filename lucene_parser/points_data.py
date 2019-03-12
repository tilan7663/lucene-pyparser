import json

from .kd_tree_reader import KDTreeReader
from .file_reader import FileReader	
from .utils import *

class PointsData(FileReader):
	extension = ".dim"
	def __init__(self, segment_info, points_index):
		super(PointsData, self).__init__(segment_info)
		self.f = self.get_file_ptr()
		self.points_index = points_index
		self.points_reader = {}

	def parse_points_data(self):
		print("#######################################################")
		print("##################### POINTS INDEX ####################")
		print("#######################################################")

		offset = self.offset
		f = self.f
		f.seek(self.offset)
		print_header(*parse_header(f))

		points_reader = {}
		for field_num, entry in self.points_index:
			ptr = entry["offset"]
			reader = KDTreeReader(f, offset, ptr)
			points_reader[field_num] = reader

		self.points_reader = points_reader

	def __iter__(self):
		for field_num, reader in self.points_reader.items():
			yield field_num, reader
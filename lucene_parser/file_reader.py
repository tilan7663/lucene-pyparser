import os

class FileReader(object):

	def __init__(self, segment_info):
		self.segment_info = segment_info
		self.is_compound_file = segment_info.is_compound_file
	
	def get_file_ptr(self):
		extension = self.extension
		if self.is_compound_file:
			self.offset = self.segment_info.file_map[extension]["offset"]
			self.length = self.segment_info.file_map[extension]["length"]

			compound_data_file = self.segment_info.name + ".cfs"
			compound_data_path = os.path.join(self.segment_info.base_path, compound_data_file)
			f = open(compound_data_path, "rb")
		else:
			self.offset = 0
			self.length = -1
			field_info_file = self.segment_info.name + extension
			field_info_path = os.path.join(self.segment_info.base_path, field_info_file)
			f = open(field_info_path, "rb")

		return f

	def set_fp_end(self):
		if self.is_compound_file:
			self.f.seek(self.offset + self.length)
		else:
			self.f.seek(0, 2)
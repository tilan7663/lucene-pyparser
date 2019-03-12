import json

from .file_reader import FileReader
from .utils import *

class DocValuesData(FileReader):
	extension = "_Lucene54_0.dvd"

	def __init__(self, segment_info, doc_values_meta):
		super(DocValuesData, self).__init__(segment_info)
		self.doc_values_meta = doc_values_meta
		self.f = self.get_file_ptr()

	def parse_doc_values_data(self):
		print("#######################################################")
		print("#################### Doc Values Data ##################")
		print("#######################################################")

		f_data = self.f
		offset = self.offset
		field_entry_map = self.doc_values_meta.field_entry_map
		segment_size = self.segment_info.segment_size

		f_data.seek(offset)
		print_header(*parse_header(f_data))

		get_docs_with_field(field_entry_map, segment_size, f_data, offset)
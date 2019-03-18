from .file_reader import FileReader
from .utils import *

class PosReader(FileReader):
	extension = "_Lucene50_0.pos"
	def __init__(self, segment_info):
		super(PosReader, self).__init__(segment_info)
		self.f = self.get_file_ptr()

	def parse_pos_reader(self):
		print("#######################################################")
		print("###################### POS READER #####################")
		print("#######################################################")

		f = self.f
		offset = self.offset

		f.seek(offset)
		print_header(*parse_header(f))

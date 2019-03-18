from .file_reader import FileReader
from .utils import *

class DocReader(FileReader):
	extension = "_Lucene50_0.doc"
	def __init__(self, segment_info):
		super(DocReader, self).__init__(segment_info)
		self.f = self.get_file_ptr()

	def parse_doc_reader(self):
		print("#######################################################")
		print("###################### DOC READER #####################")
		print("#######################################################")

		f = self.f
		offset = self.offset

		f.seek(offset)
		print_header(*parse_header(f))
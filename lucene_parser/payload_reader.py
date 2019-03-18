from .file_reader import FileReader

class PayloadReader(FileReader):
	extension = "_Lucene50_0.pay"
	def __init__(self, segment_info):
		super(PayloadReader, self).__init__(segment_info)
		self.f = self.get_file_ptr()

	def parse_payload_reader(self):
		print("#######################################################")
		print("#################### PAYLOAD READER ###################")
		print("#######################################################")

		f = self.f
		offset = self.offset

		f.seek(offset)
		print_header(*parse_header(f))

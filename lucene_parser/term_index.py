from .file_reader import FileReader
from .utils import *

class TermIndex(FileReader):
	extension = "_Lucene50_0.tip"
	def __init__(self, segment_info):
		super(TermIndex, self).__init__(segment_info)
		self.f = self.get_file_ptr()

	def parse_term_index(self):
		print("#######################################################")
		print("###################### TERM INDEX #####################")
		print("#######################################################")
		f = self.f
		offset = self.offset

		f.seek(offset)
		print_header(*parse_header(f))

		self.seek_per_field_detail()

	def seek_per_field_detail(self):
		self.set_fp_end()
		f = self.f
		f.seek(-24, 1)
		index_dir_offset = read_long(f)

		footer_magic, checksum_algo, checksum = parse_footer(f)
		actual_checksum = compute_checksum(f, self.offset, self.length)
		print_footer(footer_magic, checksum_algo, checksum, actual_checksum)
		f.seek(self.offset + index_dir_offset)

	def get_next_index_fp(self):
		return read_vlong(self.f)
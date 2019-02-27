import os

from .segment_info import SegmentInfo
from .segment_infos import SegmentInfos
from .utils import *


class ShardParser(object):
	def __init__(self, path, generation):
		self.path = path
		self.generation = generation
		self.segment_infos = SegmentInfos(generation)


	def load_segments_infos(self):
		segments_gen = self.segment_infos.segments_gen()
		segments_gen_path = os.path.join(self.path, segments_gen)

		print("#######################################################")
		print("#################### SEGMENT INFOS ####################")
		print("#######################################################")

		with open(segments_gen_path, "rb") as f:
			print_header(*parse_header(f))

			major, minor, bug = parse_version(f)
			print("Lucene version: {}.{}.{}".format(major, minor, bug))

			# counter tracks document add, delete
			index_update_count = read_long(f)
			print("index ops count: {}".format(index_update_count))

			name_counter = read_int(f)
			print("name counter: {}".format(name_counter))

			segment_count = read_int(f)
			print("number of segments: {}".format(segment_count))

			major = read_byte(f)
			minor = read_byte(f)
			bug = read_byte(f)
			print("Lucene Min segments version: major {}, minor {}, bug {}".format(major, minor, bug))

			for i in range(segment_count):
				seg_name = read_string(f)
				has_segment = hexify(f.read(1))
				segment_id = hexify(f.read(16))
				# codec of actual lucene segment file
				seg_codec = read_string(f)
				del_gen = hexify(f.read(8))
				del_count = read_int(f)
				field_info_gen = hexify(f.read(8))
				doc_values_gen = hexify(f.read(8))

				field_info_files = read_string_set(f)
				dv_field_count = intfy(f.read(4))
				if dv_field_count == 0:
					dv_fields = None
				else:
					dv_fields = read_string_set_map(f, dv_field_count)

				metadata = {
					"seg_name": seg_name,
					"has_segment": has_segment,
					"segment_id": segment_id,
					"codec": seg_codec,
					"del_gen": del_gen,
					"del_count": del_count,
					"field_info_gen": field_info_gen,
					"doc_values_gen": doc_values_gen,
					"field_info_files": field_info_files,
					"dv_field_count": dv_field_count,
					"dv_fields": dv_fields
				}


				segment_info = SegmentInfo(self.path, seg_name, metadata)

				self.segment_infos.add(seg_name, segment_info)

			user_data = read_string_map(f)
			print("SegmentInfos user data: {}".format(user_data))

			footer_magic, checksum_algo, checksum = parse_footer(f)
			actual_checksum = compute_checksum(f)
			print_footer(footer_magic, checksum_algo, checksum, actual_checksum)

	def get_segment_infos(self):
		return self.segment_infos

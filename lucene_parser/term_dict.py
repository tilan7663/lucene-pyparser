import copy
import io
import json
import os

from .constants import *
from .term_enum_frame import TermEnumFrame
from .file_reader import FileReader
from .utils import *

OUTPUT_FLAGS_NUM_BITS = 2
OUTPUT_FLAG_IS_FLOOR = 0x1
OUTPUT_FLAG_HAS_TERMS = 0x2


class TermDict(FileReader):
	extension = "_Lucene50_0.tim"
	def __init__(self, segment_info, term_index, field_infos):
		super(TermDict, self).__init__(segment_info)
		self.f = self.get_file_ptr()
		self.term_index = term_index
		self.field_infos = field_infos
		self.term = b''
		self.frames = []

	def parse_term_dict(self):
		print("#######################################################")
		print("#################### TERM DICTIONARY ##################")
		print("#######################################################")

		f_dict = self.f
		offset = self.offset
		field_infos = self.field_infos

		f_dict.seek(offset)
		print_header(*parse_header(f_dict))
		self.seek_per_field_detail()

		fields = {}
		num_fields = read_vint(f_dict)
		for i in range(num_fields):
			index_start_ptr = read_vlong(self.term_index.f)

			field_number = read_vint(f_dict)
			num_terms = read_vlong(f_dict)
			num_bytes = read_vint(f_dict)
			root_code = f_dict.read(num_bytes)
			field_info = field_infos[field_number]
			field_name = field_info["field_name"]

			fields[field_name] = {}
			index_opts = field_info["index_option_bits"]
			if index_opts == INDEX_OPTION_DOCS:
				sum_total_term_freq = -1
			else:
				sum_total_term_freq = read_vlong(f_dict)

			sum_doc_freq = read_vlong(f_dict)
			doc_count = read_vint(f_dict)
			longs_size = read_vint(f_dict)

			min_term = read_byteref(f_dict)
			max_term = read_byteref(f_dict)


			fields[field_name]["num_terms"] = num_terms
			fields[field_name]["num_bytes"] = num_bytes
			fields[field_name]["root_code"] = root_code
			fields[field_name]["index_opts"] = index_opts
			fields[field_name]["min_term"] = min_term
			fields[field_name]["max_term"] = max_term
			fields[field_name]["sum_doc_freq"] = sum_doc_freq
			fields[field_name]["doc_count"] = doc_count
			fields[field_name]["longs_size"] = longs_size
			fields[field_name]["index_start_ptr"] = index_start_ptr
			fields[field_name]["sum_total_term_freq"] = sum_total_term_freq

			# root_code_f = io.BufferedReader(io.BytesIO(root_code))
			# root_block_long = read_vlong(root_code_f)

			# root_block_fp = root_block_long >> OUTPUT_FLAGS_NUM_BITS
			# has_term = root_block_long & OUTPUT_FLAG_HAS_TERMS
			# is_floor = root_block_long & OUTPUT_FLAG_IS_FLOOR

			# fields[field_name]["root_block_fp"] = root_block_fp
			# fields[field_name]["has_term"] = has_term
			# fields[field_name]["is_floor"] = is_floor
			fields[field_name]["field_number"] = field_number

		self.fields = fields

	def seek_per_field_detail(self):
		self.set_fp_end()
		f = self.f
		f.seek(-24, 1)
		dict_dir_offset = read_long(f)

		footer_magic, checksum_algo, checksum = parse_footer(f)
		actual_checksum = compute_checksum(f, self.offset, self.length)
		print_footer(footer_magic, checksum_algo, checksum, actual_checksum)
		f.seek(self.offset + dict_dir_offset)

	def _push_frame(self, frame, length, fp):
		if frame.fp_orig == fp and f.next_ent != -1:
			raise Exception("not implemented")
		frame.next_ent = -1
		frame.prefix = length
		frame.fp = fp
		frame.fp_orig = fp
		frame.last_sub_fp = -1

		# print("push new frame fp {}, ord {}".format(fp, frame.ord))

	def set_floor_data(self, frame, scratch_reader, source):
		num_bytes = len(source) - (scratch_reader.tell() - 0)

		# read all the remaining bytes / read all the way to the end 
		floor_data = scratch_reader.read(num_bytes)

		floor_reader = io.BufferedReader(io.BytesIO(floor_data))
		frame.num_follow_floor_blocks = read_vint(floor_reader)
		frame.next_floor_label = read_byte(floor_reader)
		frame.floor_data_reader = floor_reader

	def push_frame(self, root_code, length, field_info, field):
		frame = TermEnumFrame(self, field_info, field)

		scratch_reader = io.BufferedReader(io.BytesIO(root_code))
		root_block_long = read_vlong(scratch_reader)
		
		root_block_fp = root_block_long >> OUTPUT_FLAGS_NUM_BITS
		has_terms = (root_block_long & OUTPUT_FLAG_HAS_TERMS) != 0
		is_floor = (root_block_long & OUTPUT_FLAG_IS_FLOOR) != 0

		assert(len(self.frames) == 0)
		frame.ord = 0
		frame.has_terms = has_terms
		frame.is_floor = is_floor

		if frame.is_floor:
			# print("is floor block: {}".format(field_name))
			self.set_floor_data(frame, scratch_reader, root_code)

		self._push_frame(frame, length, root_block_fp)
		self.frames.append(frame)
		return frame

	def parse_posting(self, field_name):
		self.term = b''
		self.frames = []

		field = self.fields[field_name]
		field_info = self.field_infos[field["field_number"]]
		
		root_code = field["root_code"]
		# print("root_code {}".format(root_code))
		frame = self.push_frame(root_code, 0, field_info, field)
		frame.load_block()

		while True:
			while frame.next_ent == frame.ent_count:
				# print("self.is_last_in_floor {}".format(frame.is_last_in_floor))
				if not frame.is_last_in_floor:
					# raise Exception("not implemented")
					frame.load_next_floor_block()
					# print("is leaf {}".format(frame.is_leaf_block))
					break
				else:
					# raise Exception("not implemented")
					if frame.ord == 0:
						return

					last_fp = frame.fp_orig
					frame = self.frames[frame.ord - 1]

					if frame.next_ent == -1 or frame.last_sub_fp != last_fp:
						raise Exception("not implemented")
						frame.scan_to_floor_frame(self.term)
						frame.load_block()
						frame.scan_to_sub_block(last_fp)

			while True:
				load, meta = frame.next()
				suffix = meta["suffix"]
				# print("suffix load {} {}".format(load, suffix))
				self.term = self.term[:frame.prefix] + suffix
				if load is True:
					next_ord = frame.ord + 1
					last_sub_fp = frame.last_sub_fp

					# for i, frame in enumerate(self.frames):
						# print("frame {}, ord {}".format(i, frame.ord))

					if len(self.frames) > next_ord:
						frame = self.frames[next_ord]
						assert(next_ord == frame.ord)
					else:
						frame = TermEnumFrame(self, field_info, field)
						frame.ord = next_ord
						assert(len(self.frames) == next_ord)
						self.frames.append(frame)

					self._push_frame(frame, len(self.term), last_sub_fp)
					frame.load_block()
				else:
					yield self.term, meta
					break
	
	def __getitem__(self, field_name):
		return self.fields[field_name]

	def __iter__(self):
		for field_name, _ in self.fields.items():
			yield field_name

	# def __str__(self):
		# return json.dumps(self.fields, sort_keys=False, indent=4)

import os

from .constants import *
from .utils import *


class TermEnumFrame(object):
	def __init__(self, term_dict, field_info, field):
		self.f = None
		self.has_terms = False
		self.is_floor = False
		self.version_auto_prefix = False
		self.fp = -1
		self.fp_end = -1
		self.suffix_reader = None
		self.stats_reader = None
		self.floor_data_reader = None
		self.metadata_reader = None
		self.prefix = 0
		self.ent_count = 0
		self.next_ent = -1
		# True if block is not a floor block or it is the last sub-block of a floor block
		self.is_last_in_floor = False
		self.is_leaf_block = False
		self.last_sub_fp = 0
		self.next_floor_label = -1
		self.num_follow_floor_blocks = -1
		self.term_dict = term_dict
		self.meta_data_upto = 0
		self.sub_code = 0
		self.ord = -1
		self.fp_orig = -1
		self.field_info = field_info
		self.field = field

	def init_terms_in(self):
		if self.f is None:
			f = self.term_dict.f
			fd = os.dup(f.fileno())
			self.f = os.fdopen(fd, "rb")
			self.offset = self.term_dict.offset


	def load_block(self):
		self.init_terms_in()
		
		f = self.f
		offset = self.offset

		# Don't know how does this work, but you need this line for file to be seek properly
		f.seek(0)
		# total = f.read(-1)
		# print("max len {}".format(len(total)))

		if self.next_ent != -1:
			return

		# print("load block start fp: {}".format(self.fp))
		f.seek(offset + self.fp)
		# print("set offset {}".format(f.tell()))

		code = read_vint(f)
		self.ent_count = code >> 1
		# print("load block ent_count {}, frame.ord {}, fp {}".format(self.ent_count, self.ord, self.fp))
		assert(self.ent_count > 0)

		self.is_last_in_floor = (code & 1) != 0
		code = read_vint(f)
		self.is_leaf_block = (code & 1) != 0
		
		# assert(self.is_last_in_floor or self.is_floor)

		# read suffix bytes
		num_bytes = code >> 1
		suffix_bytes = f.read(num_bytes)
		self.suffix_reader = io.BufferedReader(io.BytesIO(suffix_bytes))

		num_bytes = read_vint(f)
		stats_bytes = f.read(num_bytes)
		self.stats_reader = io.BufferedReader(io.BytesIO(stats_bytes))

		num_bytes = read_vint(f)
		metadata_bytes = f.read(num_bytes)
		self.metadata_reader = io.BufferedReader(io.BytesIO(metadata_bytes))

		self.meta_data_upto = 0
		self.next_ent = 0
		self.last_sub_fp = -1

		# print("self.fp {}".format(self.fp_end))
		self.fp_end = f.tell()

		self.doc_start_fp = 0
		self.pos_start_fp = 0
		self.payload_start_fp = 0

	def load_next_floor_block(self):
		self.fp = self.fp_end
		self.next_ent = -1
		self.load_block()

	def decode_meta(self):
		index_opts = self.field_info["index_option_bits"]
		field_has_payload = self.field_info["store_payload"]
		field_has_position = index_opts >= INDEX_OPTION_DOCS_FREQS_POSITIONS
		field_has_offset = index_opts >= INDEX_OPTION_DOCS_FREQS_POSITIONS_OFFSETS
		longs_size = self.field["longs_size"]

		doc_freq = read_vint(self.stats_reader)
		if index_opts != INDEX_OPTION_DOCS:
			total_term_freq = doc_freq + read_vlong(self.stats_reader)
		else:
			total_term_freq = doc_freq

		self.doc_start_fp += read_vlong(self.metadata_reader)
		if field_has_position:
			self.pos_start_fp += read_vlong(self.metadata_reader)
			if field_has_offset or field_has_payload:
				self.payload_start_fp += read_vlong(self.metadata_reader)
				assert(longs_size == 3)
			else:
				assert(longs_size == 2)
		else:
			assert(longs_size == 1)

		if doc_freq == 1:
			singleton_doc_id = read_vint(self.metadata_reader)
		else:
			singleton_doc_id = -1

		if field_has_position:
			if total_term_freq > BLOCK_SIZE:
				last_pos_block_offset = read_vlong(self.metadata_reader)
			else:
				last_pos_block_offset = -1

		if doc_freq > BLOCK_SIZE:
			skip_offset = read_vlong(self.metadata_reader)
		else:
			skip_offset = -1

		return {"doc_freq": doc_freq, "doc_start_fp": self.doc_start_fp, "pos_start_fp": self.pos_start_fp, "payload_start_fp": self.payload_start_fp,
		        "skip_offset": skip_offset, "total_term_freq": total_term_freq, "singleton_doc_id": singleton_doc_id}


	def next_leaf(self):
		self.next_ent += 1
		suffix_length = read_vint(self.suffix_reader)
		suffix = self.suffix_reader.read(suffix_length)
		meta_data = self.decode_meta()
		meta_data["suffix"] = suffix
		return False, meta_data

	def next_non_leaf(self):
		while True:
			if self.next_ent == self.ent_count:
				self.load_next_floor_block()
				if self.is_leaf_block:
					return self.next_leaf()
				else:
					continue

			self.next_ent += 1
			code = read_vint(self.suffix_reader)
			if self.version_auto_prefix == False:
				suffix_length = code >> 1
				suffix_term = self.suffix_reader.read(suffix_length)
				if (code & 1) == 0:
					self.sub_code = 0
					meta_data = self.decode_meta()
					meta_data["suffix"] = suffix_term
					return False, meta_data
				else:
					self.sub_code = read_vlong(self.suffix_reader)
					self.last_sub_fp = self.fp - self.sub_code
					return True, {"suffix": suffix_term}
			else:
				raise Exception("not supported")

	def next(self):
		if self.is_leaf_block:
			return self.next_leaf()
		else:
			return self.next_non_leaf()

	def scan_to_floor_frame(self, term):
		if not self.is_floor or len(term) <= self.prefix:
			return
		
		target_lable = term[self.prefix]
		if target_lable < self.next_floor_label:
			return

		assert self.num_follow_floor_blocks != 0

		new_fp = self.fp_orig
		while True:
			code = read_vlong(self.floor_data_reader)
			new_fp = self.fp_orig + (code >> 1)
			self.has_terms = (code & 1) != 0
			self.is_last_in_floor = self.num_follow_floor_blocks == 1
			self.num_follow_floor_blocks -= 1
			if self.is_last_in_floor:
				self.next_floor_label = 256
				break
			else:
				self.next_floor_label = read_byte(self.floor_data_reader)
				if target_lable < self.next_floor_label:
					break

		if new_fp != self.fp:
			self.next_ent = -1
			self.fp = new_fp
		else:
			pass

	def scan_to_sub_block(self, sub_fp):
		assert(self.is_leaf_block == False)
		if self.last_sub_fp == sub_fp:
			return

		assert(sub_fp < self.fp)
		target_sub_code = self.fp - sub_fp
		while True:
			assert self.next_ent < self.ent_count
			self.next_ent += 1
			code = read_vint(self.suffix_reader)

			if self.version_auto_prefix == False:
				# skip bytes
				self.suffix_reader.read(code >> 1)
				if (code & 1) != 0:
					sub_code = read_vlong(self.suffix_reader)
					if target_sub_code == sub_code:
						self.last_sub_fp = sub_fp
						return
				else:
					# termBlockOrd++
					pass

			else:
				raise Exception("not supported")

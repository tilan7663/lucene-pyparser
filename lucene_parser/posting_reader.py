import json
import math

from .constants import *
from .doc_reader import DocReader
from .payload_reader import PayloadReader
from .pos_reader import PosReader
from .utils import *

class PostingReader(object):
	def __init__(self, segment_info, field_infos):
		self.field_infos = field_infos
		self.doc_reader = DocReader(segment_info)
		self.doc_reader.parse_doc_reader()

		if field_infos.has_prox():
			self.pos_reader = PosReader(segment_info)
			self.pos_reader.parse_pos_reader()

			if field_infos.has_payloads() or field_infos.has_offsets():
				self.payload_reader = PayloadReader(segment_info)
				self.payload_reader.parse_payload_reader

		self.init_for_util()

	def parse_posting(self, term_state, field_info):
		index_opts = field_info["index_option_bits"]
		total_term_freq = term_state["total_term_freq"]
		doc_freq = term_state["doc_freq"]
		singleton_doc_id = term_state["singleton_doc_id"]


		doc_ids = []
		index_has_freq = index_opts >= INDEX_OPTION_DOCS_FREQS

		f_doc = self.doc_reader.f
		offset = self.doc_reader.offset

		if doc_freq > 1:
			# set the .doc position to the beginning of the block
			f_doc.seek(offset + term_state["doc_start_fp"])

		doc = -1
		doc_up_to = 0
		buffer_up_to = BLOCK_SIZE
		accum = 0
		doc_delta_buffer = [0] * BLOCK_SIZE

		doc_ids = []
		while doc_up_to < doc_freq:
			if buffer_up_to == BLOCK_SIZE:
				self.refill_docs(f_doc, doc_delta_buffer, index_has_freq, singleton_doc_id, doc_freq - doc_up_to, doc_freq)
				buffer_up_to = 0

			# index = doc_up_to % BLOCK_SIZE 				
			accum += doc_delta_buffer[buffer_up_to]
			doc_up_to += 1

			doc = accum
			buffer_up_to += 1

			doc_ids.append(accum)

		# print("total_term_freq {} field_info {}, total {}".format(doc_freq, field_info["field_name"], len(doc_ids)))
		return doc_ids

	def refill_docs(self, f_doc, doc_delta_buffer, index_has_freq, singleton_doc_id, left, doc_freq):
		assert left > 0
		if left >= BLOCK_SIZE:
			# readBlock
			self.read_block(f_doc, doc_delta_buffer)
			if index_has_freq:
				# skip frequency
				self.skip_block(f_doc)

		elif doc_freq == 1:
			# special case
			doc_delta_buffer[0] = singleton_doc_id
		else:
			self.parse_posting_vint_block(f_doc, doc_delta_buffer, index_has_freq, left)

	def read_block(self, f_doc, buffers):
		num_bits = read_byte(f_doc)
		assert num_bits <= 32

		if num_bits == ALL_VALUES_EQUAL:
			value = read_vint(f_doc)
			for i in range(BLOCK_SIZE):
				buffers[i] = value
				return

		encoded_size = self.encoded_sizes[num_bits]["encoded_size"]
		encoded_bytes = f_doc.read(encoded_size)
		decoded_values = self.decode(self.encoded_sizes[num_bits]["format_id"],
			        self.encoded_sizes[num_bits]["bits_per_value"],
			        encoded_bytes)

		assert(len(buffers) == len(decoded_values))
		assert(len(buffers) == BLOCK_SIZE)

		for i in range(BLOCK_SIZE):
			buffers[i] = decoded_values[i]

	def skip_block(self, f_doc):
		num_bits = read_byte(f_doc)
		if num_bits == ALL_VALUES_EQUAL:
			read_vint(f_doc)
			return

		assert num_bits > 0 and num_bits <= 32
		encoded_size = self.encoded_sizes[num_bits]["encoded_size"]
		if encoded_size is None:
			raise Exception("not implemented")

		f_doc.seek(f_doc.tell() + encoded_size)

	def parse_posting_vint_block(self, f_doc, doc_delta_buffer, index_has_freq, left):
		if index_has_freq:
			for i in range(left):
				code = read_vint(f_doc)
				doc_delta_buffer[i] = code >> 1
				if code & 1:
					_freq = 1
				else:
					_freq = read_vint(f_doc)
		else:
			for i in range(left):
				doc_delta_buffer[i] = read_vint(f_doc)

	def encode_size(self, format_id, value_count, bits_per_value):
		if format_id == 0:
			byte_count = math.ceil(value_count * bits_per_value / 8)
			assert byte_count >= 0 and byte_count < 2 ** 31
			return byte_count
		else:
			values_per_block = 64 / bits_per_value

			long_count = math.ceil(value_count / values_per_block)
			return 8 * long_count

	def init_for_util(self):
		f = self.doc_reader.f

		packed_int_version = read_vint(f)
		encoded_sizes = {}
		for i in range(1, 33):
			code = read_vint(f)
			format_id = code >> 5
			bits_per_value = (code & 31) + 1
			encoded_size = self.encode_size(format_id, BLOCK_SIZE, bits_per_value)
			encoded_sizes[i] = {}
			encoded_sizes[i]["format_id"] = format_id
			encoded_sizes[i]["bits_per_value"] = bits_per_value
			encoded_sizes[i]["code"] = code
			encoded_sizes[i]["encoded_size"] = encoded_size

		self.encoded_sizes = encoded_sizes

	def decode(self, format_id, bits_per_value, encoded_bytes):
		if format_id == PACKED:
			if bits_per_value == 3:
				iterations = int(len(encoded_bytes) / 3)
				reader = io.BufferedReader(io.BytesIO(encoded_bytes))
				values = []
				for i in range(iterations):
					_bytes = intfy(reader.read(3))
					
					value = (_bytes >> 21) & 7
					values.append(value)
					value = (_bytes >> 18) & 7
					values.append(value)
					value = (_bytes >> 15) & 7
					values.append(value)
					value = (_bytes >> 12) & 7
					values.append(value)
					value = (_bytes >> 9) & 7
					values.append(value)
					value = (_bytes >> 6) & 7
					values.append(value)
					value = (_bytes >> 3) & 7
					values.append(value)
					value = _bytes & 7
					values.append(value)

				return values
			elif bits_per_value == 9:
				assert(len(encoded_bytes) == 144)
				iterations = int(len(encoded_bytes) / 9)
				reader = io.BufferedReader(io.BytesIO(encoded_bytes))
				values = []
				mask = (2 << 9) - 1
				for i in range(iterations):
					_bytes = intfy(reader.read(3))
					value = (_bytes >> 63) & mask
					values.append(value)
					value = (_bytes >> 54) & mask
					values.append(value)
					value = (_bytes >> 45) & mask
					values.append(value)
					value = (_bytes >> 36) & mask
					values.append(value)
					value = (_bytes >> 27) & mask
					values.append(value)
					value = (_bytes >> 18) & mask
					values.append(value)
					value = (_bytes >> 9) & mask
					values.append(value)
					value = _bytes & mask
					values.append(value)

				return values
			else:
				raise Exception("bits_per_value corrupted {}".format(bits_per_value))
		elif format_id == PACKED_SINGLE_BLOCK:
			values = []
			if bits_per_value == 1:
				for _byte in encoded_bytes:
					value = (_byte >> 7) & 1
					values.append(value)
					value = (_byte >> 6) & 1
					values.append(value)
					value = (_byte >> 5) & 1
					values.append(value)
					value = (_byte >> 4) & 1
					values.append(value)
					value = (_byte >> 3) & 1
					values.append(value)
					value = (_byte >> 2) & 1
					values.append(value)
					value = (_byte >> 1) & 1
					values.append(value)
					value = _byte & 1
					values.append(value)

				return values
			else:
				raise Exception("bits_per_value corrupted")
		else:
			raise Exception("format id corrupted")

	def __str__(self):
		return json.dumps(self.encoded_sizes, sort_keys=False, indent=4)

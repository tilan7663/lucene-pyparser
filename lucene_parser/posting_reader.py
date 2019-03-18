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
				
			accum += doc_delta_buffer[doc_up_to]
			doc_up_to += 1

			doc = accum
			buffer_up_to += 1

			doc_ids.append(accum)

		return doc_ids

	def refill_docs(self, f_doc, doc_delta_buffer, index_has_freq, singleton_doc_id, left, doc_freq):
		assert left > 0
		if left > BLOCK_SIZE:
			# readBlock
			raise Exception("not implemented yet")
		elif doc_freq == 1:
			# special case
			doc_delta_buffer[0] = singleton_doc_id
		else:
			self.parse_posting_vint_block(f_doc, doc_delta_buffer, index_has_freq, left)

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

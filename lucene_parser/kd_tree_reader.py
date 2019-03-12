import os

from .intersect_state import IntersectState
from .packed_index_tree import PackedIndexTree
from .utils import *

VERSION_START = 0
VERSION_COMPRESSED_DOC_IDS = 1
VERSION_COMPRESSED_VALUES = 2
VERSION_IMPLICIT_SPLIT_DIM_1D = 3
VERSION_PACKED_INDEX = 4
VERSION_CURRENT = VERSION_PACKED_INDEX

class KDTreeReader(object):
	def __init__(self, f, offset, ptr):
		print("#######################################################")
		print("#################### KD-TREE READER ###################")
		print("#######################################################")

		fd = os.dup(f.fileno())
		f = os.fdopen(fd, "rb")
		self.f = f

		f.seek(offset + ptr)
		header_magic, name, version = parse_header(f, suffix=False)

		print_header(header_magic, name, version)

		num_dims = read_vint(f)
		max_point_in_leaf = read_vint(f)
		bytes_per_dim = read_vint(f)
		version = intfy(version)

		if num_dims == 1 and version >= VERSION_IMPLICIT_SPLIT_DIM_1D:
			bytes_per_index_entry = bytes_per_dim
		else:
			bytes_per_index_entry = bytes_per_dim + 1

		packed_bytes_length = num_dims * bytes_per_dim

		# read index
		num_leaves = read_vint(f)
		assert(num_leaves > 0)
		leaf_node_offset = num_leaves

		min_packed_values = f.read(packed_bytes_length)
		max_packed_values = f.read(packed_bytes_length)

		# how many unique values
		point_count = read_vlong(f)

		# how many docs
		doc_count = read_vint(f)

		print("num_dims {}".format(num_dims))
		print("max_point_in_leaf {}".format(max_point_in_leaf))
		print("bytes_per_dim {}".format(bytes_per_dim))
		print("point_count {}".format(point_count))
		print("doc_count {}".format(doc_count))


		if version >= VERSION_PACKED_INDEX:
			num_bytes = read_vint(f)
			packed_index = f.read(num_bytes)
		else:
			raise Exception("not implemented")

		self.num_leaves = num_leaves
		self.leaf_node_offset = num_leaves
		self.min_packed_values = min_packed_values
		self.max_packed_values = max_packed_values
		self.num_dims = num_dims
		self.max_point_in_leaf = max_point_in_leaf
		self.bytes_per_dim = bytes_per_dim
		self.doc_count = doc_count
		self.version = version
		self.index_tree = PackedIndexTree(packed_index, num_leaves, num_dims, bytes_per_dim, packed_bytes_length)
		self.offset = offset
		self.packed_bytes_length = packed_bytes_length

	def intersect(self):
		pass

	def get_intersect_state(self):
		return IntersectState(self.f, self.offset, self.num_dims, self.packed_bytes_length,
							  self.max_point_in_leaf, self.index_tree)

	def read_delta_vints(self, f, count):
		doc_ids = []
		doc_id = 0
		for i in range(count):
			doc_id += read_vint(f)
			doc_ids.append(doc_id)
		return doc_ids

	def read_ints_32(self, f, count):
		doc_ids = []
		for i in range(count):
			doc_ids.append(read_int(f))

		return doc_ids 

	def read_ints_24(self, f, count):
		doc_ids = []
		for i in range(count):
			doc_ids.append(intfy(f.read(3)))

		return doc_ids

	def read_docs(self, f, count):
		byte_per_value = read_byte(f)
		if byte_per_value == 0:
			return self.read_delta_vints(f, count)
		elif byte_per_value == 32:
			return self.read_ints_32(f, count)
		elif byte_per_value == 24:
			return self.read_ints_24(f, count)
		else:
			raise Exception("corrupted bytes per value")

	def visis_doc_ids(self, f, offset, block_fp):
		f.seek(offset + block_fp)
		count = read_vint(f)
		
		if self.version < VERSION_COMPRESSED_DOC_IDS:
			raise Exception("not implemented")
		else:
			doc_ids = self.read_docs(f, count)
		return count, doc_ids

	def read_common_prefix_lengths(self, f, common_prefix_lengths, scratch_packed_value):
		for i in range(self.num_dims):
			prefix = read_vint(f)
			common_prefix_lengths[i] = prefix
			if prefix > 0:
				index = i * self.bytes_per_dim
				scratch_packed_value[index:index + prefix] = f.read(prefix)

	def read_compressed_dim(self, f):
		compressed_dim = read_byte(f)
		# if compressed_dim > 127 or compressed_dim > self.num_dims:
		# (compressedDim < -1 || compressedDim >= numDims)
		if compressed_dim >= self.num_dims:
			raise Exception("corrupted compressed_dim")
		return compressed_dim

	def visit(self, doc_id, scratch_packed_value, num_dims, bytes_per_dim):
		f_pack = io.BufferedReader(io.BytesIO(bytes(scratch_packed_value)))
		for i in range(self.num_dims):
			raw = f_pack.read(bytes_per_dim)
			print("doc id {}, value {}, len {}, hex {}".format(doc_id, intfy(raw), len(scratch_packed_value), hexify(raw)))

	def visit_compressed_doc_values(self, common_prefix_lengths, scratch_packed_value, f, doc_ids, doc_count, compressed_dim):
		compressed_byte_offset = compressed_dim * self.bytes_per_dim + common_prefix_lengths[compressed_dim]
		common_prefix_lengths[compressed_dim] += 1

		i = 0
		while i < doc_count:
			scratch_packed_value[compressed_byte_offset] = read_byte(f)
			run_len = read_byte(f)
			for j in range(run_len):
				for dim in range(self.num_dims):
					prefix = common_prefix_lengths[dim]
					length_remained = self.bytes_per_dim - prefix
					bytes_remained = f.read(length_remained)
					index = dim * self.bytes_per_dim + prefix
					scratch_packed_value[index:index + length_remained] = bytes_remained

				self.visit(doc_ids[i + j], scratch_packed_value, self.num_dims, self.bytes_per_dim)
			i += run_len

		assert(i == doc_count)

	def visit_doc_values(self, f, doc_count, doc_ids, common_prefix_lengths, scratch_packed_value):
		self.read_common_prefix_lengths(f, common_prefix_lengths, scratch_packed_value)

		if self.version < VERSION_COMPRESSED_VALUES:
			raise Exception("not implemented")
		else:
			compressed_dim = self.read_compressed_dim(f)
			self.visit_compressed_doc_values(common_prefix_lengths, scratch_packed_value, f, doc_ids, doc_count, compressed_dim);

	def visit_all(self, state):
		
		if state.index_tree.is_leaf_node():
			if state.index_tree.node_exists():
				doc_count, doc_ids = self.visis_doc_ids(state.f, state.offset, state.index_tree.get_leaf_block_fp())
				self.visit_doc_values(state.f, doc_count, doc_ids, state.common_prefix_lengths, state.scratch_packed_value)
		else:
			state.index_tree.push_left();
			visit_all(state);
			state.index_tree.pop();

			state.index_tree.push_right();
			visit_all(state);
			state.index_tree.pop();

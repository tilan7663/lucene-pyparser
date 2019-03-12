import os

from .packed_index_tree import PackedIndexTree

class IntersectState(object):

	def __init__(self, f_point_data, offset, num_dims, packed_bytes_length,
		               max_points_in_leaf_node, index_tree):
		fd = os.dup(f_point_data.fileno())
		f = os.fdopen(fd, "rb")

		self.f  = f
		self.offset = offset
		self.num_dims = num_dims
		self.packed_bytes_length = packed_bytes_length
		self.max_points_in_leaf_node = max_points_in_leaf_node
		self.index_tree = index_tree
		self.common_prefix_lengths = [0] * num_dims
		self.scratch_doc_ids = [0] * max_points_in_leaf_node
		self.scratch_packed_value = [0] * packed_bytes_length

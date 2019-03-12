import io
import math

from .utils import *

class PackedIndexTree(object):

	def __init__(self, packed_index, num_leaves, num_dims, bytes_per_dim, packed_bytes_length):
		tree_depth = self.get_tree_depth(num_leaves)
		self.index_reader = io.BufferedReader(io.BytesIO(packed_index))
		self.node_id = 1
		self.level = 1
		self.split_dim = 0
		# tree_depth + 1 because tree index starts at 1
		self.split_packed_value_stack = [None] * (tree_depth + 1)
		self.leaf_block_fp_stack = [0] * (tree_depth + 1)
		self.left_node_positions = [0] * (tree_depth + 1)
		self.right_node_positions = [0] * (tree_depth + 1)
		self.split_values_stack = [None] * (tree_depth + 1)
		self.split_dims = [0] * (tree_depth + 1)
		self.negative_deltas = [False] * (num_dims * (tree_depth + 1))
		self.leaf_node_offset = num_leaves
		self.num_dims = num_dims
		self.bytes_per_dim = bytes_per_dim
		self.packed_bytes_length = packed_bytes_length

		self.split_packed_value_stack[self.level] = [0] * packed_bytes_length
		self.split_values_stack[0] = [0] * packed_bytes_length
		self.tree_depth = tree_depth

		self.read_node_data(False);

	def get_tree_depth(self, num_leaves):
	    # First +1 because all the non-leave nodes makes another power
	    # of 2; e.g. to have a fully balanced tree with 4 leaves you
	    # need a depth=3 tree:

	    # Second +1 because MathUtil.log computes floor of the logarithm; e.g.
	    # with 5 leaves you need a depth=4 tree:
		return int(math.log(num_leaves, 2)) + 2

	def is_leaf_node(self):
		return self.node_id >= self.leaf_node_offset

	def node_exists(self):
		return self.node_id - self.leaf_node_offset < self.leaf_node_offset;

	def _push_left(self):
		self.node_id *= 2
		self.level += 1
		if self.split_packed_value_stack[level] is None:
			# initialize the bytes array
			self.split_packed_value_stack[level] = [0] * self.packed_bytes_length

	def push_left(self):
		node_position = self.left_node_positions[self.level]
		self._push_left()
		source_index = (self.level - 1) * self.num_dims
		dest_index = self.level * self.num_dims

		self.negative_deltas[dest_index:dest_index + self.num_dims] = self.negative_deltas[source_index:source_index + self.num_dims]
		self.negative_deltas[self.level * self.num_dims + self.split_dim] = True
		self.index_reader.seek(node_position)
		self.read_node_data(True)

		assert(self.split_dim != -1)

	def _push_right(self):
		self.node_id = self.node_id * 2 + 1
		self.level += 1
		if self.split_packed_value_stack[level] is None:
			# initialize the bytes array
			self.split_packed_value_stack[level] = [0] * self.packed_bytes_length

	def push_right(self):
		node_position = self.right_node_positions[self.level]
		self._push_right()
		source_index = (self.level - 1) * self.num_dims
		dest_index = self.level * self.num_dims

		self.negative_deltas[dest_index:dest_index + self.num_dims] = self.negative_deltas[source_index:source_index + self.num_dims]
		self.negative_deltas[self.level * self.num_dims + self.split_dim] = False
		self.index_reader.seek(node_position)
		self.read_node_data(False)

	def _pop(self):
		self.node_id /= 2
		self.level -= 1
		self.split_dim = -1

	def pop(self):
		self._pop()
		self.split_dim = self.split_dims[self.level]

	def read_node_data(self, is_left):
		self.leaf_block_fp_stack[self.level] = self.leaf_block_fp_stack[self.level - 1]
		if is_left is False:
			self.leaf_block_fp_stack[self.level] += read_vlong(self.index_reader)
      	
		if self.is_leaf_node():
			self.split_dim = -1
		else:
			code = read_vint(self.index_reader)
			self.split_dim = code % num_dims
			self.split_dims[self.level] = self.split_dim
			code /= self.num_dims
			prefix = code % (1 + self.bytes_per_dim)
			suffix = self.bytes_per_dim - prefix

			if self.split_values_stack[self.level] is None:
				self.split_values_stack[self.level] = [0] * self.packed_bytes_length

			self.split_values_stack[self.level][0:0 + self.packed_bytes_length] = self.split_values_stack[self.level-1][0:0 + self.packed_bytes_length]
			if suffix > 0:
				first_diff_byte_delta = code / (1 + self.bytes_per_dim)
				if self.negative_deltas[self.level * self.num_dims + self.split_dim]:
					first_diff_byte_delta = -first_diff_byte_delta

				old_byte = self.split_values_stack[self.level][self.split_dim * self.bytes_per_dim + prefix] & 0xff
				self.split_values_stack[self.level][self.split_dim * self.bytes_per_dim + prefix] = old_byte + first_diff_byte_delta
				split_values = self.index_reader.read(suffix - 1)
				
				start_pos = self.split_dim * self.bytes_per_dim + prefix + 1
				end_pos = start_pos + suffix - 1
				self.split_values_stack[self.level][start_pos:end_pos] = split_values
			else:
				pass

			if self.node_id * 2 < self.leaf_node_offset:
				left_num_bytes = read_vint(self.index_reader)
			else:
				left_num_bytes = 0

			self.left_node_positions[self.level] = self.index_reader.tell()
			self.right_node_positions[self.level] = self.left_node_positions[self.level] + left_num_bytes

	def get_leaf_block_fp(self):
		assert(self.is_leaf_node())
		return self.leaf_block_fp_stack[self.level]

from .utils import *

BLOCK_SIZE = 64
BLOCK_BITS = 6
MOD_MASK = BLOCK_SIZE - 1
MASK = 0xffffffffffffffff

class Pack64(object):

	def __init__(self, f, num_values, bits_per_value, signed=False):
		b_count = byte_count(num_values, bits_per_value)
		l_count = long_count(num_values, bits_per_value)

		blocks = []
		for i in range(int(b_count / 8)):
			# read long
			# blocks.append(f.read(8))
			blocks.append(read_long(f))

		if (b_count % 8 != 0):
			remaining = b_count % 8
			last_long = 0
			for j in range(remaining):
				last_long |= (read_byte(f) & 0xff) << (56 - j * 8) 
			# needs to convert it to bytes
			blocks.append(last_long)

		self.blocks = blocks
		
		self.mask_right = 0xffffffffffffffff << (BLOCK_SIZE - bits_per_value)
		self.mask_right = self.mask_right & 0xffffffffffffffff
		self.mask_right = self.mask_right >> (BLOCK_SIZE - bits_per_value)

		self.bpv_minus_block_size = bits_per_value - BLOCK_SIZE;
		self.bits_per_value = bits_per_value
		assert(len(blocks) == l_count)

		print("bits_per_value: {}, self.mask_right {}".format(bits_per_value, self.mask_right))
		self.signed = signed

	# right now it doesn't handle negative number yet
	# todo: handle negative bits_per_value
	def get(self, index):
		blocks = self.blocks

		major_bits_pos = index * self.bits_per_value
		element_pos = major_bits_pos >> BLOCK_BITS
		end_bits = (major_bits_pos & MOD_MASK) + self.bpv_minus_block_size
		if end_bits <= 0:
			# value can be found in a single block
			val = (blocks[element_pos] >> -end_bits) & self.mask_right
		else:
			val = (blocks[element_pos] << end_bits | blocks[element_pos + 1] >> (BLOCK_SIZE - end_bits)) & self.mask_right

		return val

	def __getitem__(self, index):
		return self.get(index)

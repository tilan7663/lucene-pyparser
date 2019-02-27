from .utils import *

class Direct_8(object):
	def __init__(self, f, num_values):
		self.blocks = []

		for i in range(num_values):
			self.blocks.append(read_byte(f))

	def get(self, index):
		return self.blocks[index]

	def __getitem__(self, index):
		return self.get(index)
class SegmentInfos(object):
	def __init__(self, generation):
		self.generation = generation
		self.segment_infos = {}

	def segments_gen(self):
		return "segments_{}".format(self.generation)

	def add(self, seg_name, seg_info):
		self.segment_infos[seg_name] = seg_info

	def get(self, seg_name):
		return self.segment_infos[seg_name]

	def __iter__(self):
		for seg_name, seg_info in self.segment_infos.items():
			yield seg_name, seg_info
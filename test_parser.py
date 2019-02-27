import json

from lucene_parser.field_data import FieldData
from lucene_parser.field_infos import FieldInfos
from lucene_parser.field_index import FieldIndex
from lucene_parser.shard_parser import ShardParser

def main():
	shard_parser = ShardParser("/home/tian/Work/lucene/index/", 5)
	shard_parser.load_segments_infos()

	for seg_name, segment_info in shard_parser.get_segment_infos():
		print("seg_name: {}, segment_info [{}]".format(seg_name, segment_info))
		segment_info.load()

		field_infos = FieldInfos(segment_info)
		field_infos.parse_field_info()

		print(field_infos)

		field_index = FieldIndex(segment_info)
		field_index.parse_field_index()
		print(field_index)

		field_data = FieldData(segment_info, field_index, field_infos)
		field_data.parse_field_data()

		# for docs in field_data:
		# 	for doc in docs:
		# 		print(json.dumps(doc, sort_keys=False, indent=4))


if __name__ == "__main__":
	main()
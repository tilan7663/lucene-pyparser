import json

from lucene_parser.doc_reader import DocReader
from lucene_parser.doc_values_data import DocValuesData
from lucene_parser.doc_values_meta import DocValuesMeta
from lucene_parser.field_data import FieldData
from lucene_parser.field_infos import FieldInfos
from lucene_parser.field_index import FieldIndex
from lucene_parser.norm_data import NormData
from lucene_parser.norm_meta import NormMeta
from lucene_parser.points_data import PointsData
from lucene_parser.points_index import PointsIndex
from lucene_parser.pos_reader import PosReader
from lucene_parser.posting_reader import PostingReader
from lucene_parser.shard_parser import ShardParser
from lucene_parser.term_dict import TermDict
from lucene_parser.term_index import TermIndex

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

		doc_values_meta = DocValuesMeta(segment_info, field_infos)
		doc_values_meta.parse_doc_values_meta()
		print(doc_values_meta)

		doc_values_data = DocValuesData(segment_info, doc_values_meta)
		doc_values_data.parse_doc_values_data()

		norm_meta = NormMeta(segment_info, field_infos)
		norm_meta.parse_norm_meta()
		print(norm_meta)

		norm_data = NormData(segment_info, norm_meta)
		norm_data.parse_norm_data()
		# print(norm_data)

		points_index = PointsIndex(segment_info, field_infos)
		points_index.parse_points_index()
		print(points_index)

		points_data = PointsData(segment_info, points_index)
		points_data.parse_points_data()

		# for field_num, reader in points_data:
		# 	print("field_num {}, reader {}".format(field_infos[field_num], reader))
		# 	state = reader.get_intersect_state()
		# 	reader.visit_all(state)

		posting_reader = PostingReader(segment_info, field_infos)
		print(posting_reader)

		term_index = TermIndex(segment_info)
		term_index.parse_term_index()

		term_dict = TermDict(segment_info, term_index, field_infos)
		term_dict.parse_term_dict()
		print(term_dict)

		for field_name in term_dict:
			terms_iter = term_dict.parse_posting(field_name)
			
			field = term_dict[field_name]
			field_info = field_infos[field["field_number"]]
			try:
				for i, term_tuple in enumerate(terms_iter):
					term = term_tuple[0]
					term_state = term_tuple[1]

					doc_ids = posting_reader.parse_posting(term_state, field_info)
					print("field name {}, id {}, term {}, doc_ids {}, len {}".format(field_name, i, term, set(doc_ids), len(set(doc_ids))))
			except Exception as e:
				print("field_name {}, msg {}".format(field_name, e))
				# raise

		# doc_reader = DocReader(segment_info)
		# doc_reader.parse_doc_reader()

		# pos_reader = PosReader(segment_info)
		# pos_reader.parse_pos_reader()

if __name__ == "__main__":
	main()
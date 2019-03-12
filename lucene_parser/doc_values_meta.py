import json

from .file_reader import FileReader
from .utils import *

class DocValuesMeta(FileReader):
	extension = "_Lucene54_0.dvm"
	def __init__(self, segment_info, field_infos):
		super(DocValuesMeta, self).__init__(segment_info)
		self.field_infos = field_infos
		self.f = self.get_file_ptr()

	def parse_doc_values_meta(self):
		print("#######################################################")
		print("#################### Doc Values Meta ##################")
		print("#######################################################")

		f_meta = self.f
		offset = self.offset
		segment_size = self.segment_info.segment_size

		f_meta.seek(offset)
		print_header(*parse_header(f_meta))

		number_fields = 0
		field_entry_map = {}
		field_infos = self.field_infos

		while True:
			field_number = read_vint(f_meta)
			# how to represent -1 in vint? (vint is not suppose to be used to encode negative number)
			if field_number == -1 or field_number == 0xffffffff:
				break

			number_fields += 1
			info = field_infos[field_number]

			field_type = read_byte(f_meta)
			info["field_type"] = field_type

			if field_type == DOC_VALUES_NUMERIC:
				entry = read_numeric_entry(f_meta, info, segment_size)
				field_entry_map[info["field_name"]] = {"numeric": entry, "info": info}
			elif field_type == DOC_VALUES_BINARY:
				entry = read_binary_entry(f_meta, info)
				field_entry_map[info["field_name"]] = {"binary": entry, "info": info}
			elif field_type == DOC_VALUES_SORTED:
				binary_entry, ord_entry = read_sorted_entry(f_meta, info, segment_size)
				field_entry_map[info["field_name"]] = {"binary": binary_entry, "ord": ord_entry, "info": info}
			elif field_type == DOC_VALUES_SORTED_SET:
				ss_entry = read_sorted_set_entry(f_meta, info)
				# field_entry_map[info["field_name"]] = ss_entry
				# print "ss_entry: ", ss_entry
				if ss_entry["format"] == DOC_SORTED_WITH_ADDRESSES:
					binary_entry, ord_entry, ord_index_entry = read_sorted_set_field_with_addr(f_meta, info)
					field_entry_map[info["field_name"]] = {"binary": binary_entry, "ord": ord_entry, "ord_index": ord_index_entry, "ss": ss_entry, "info": info}
				elif ss_entry["format"] == DOC_SORTED_SET_TABLE:
					# make sure add ss_entry to field entry map
					binary_entry, ord_entry = read_sorted_set_field_with_table(f_meta, info)
					field_entry_map[info["field_name"]] = {"binary": binary_entry, "ord": ord_entry, "ss": ss_entry, "info": info}
				elif ss_entry["format"] == DOC_SORTED_SINGLE_VALUED:
					if read_vint(f_meta) != info["field_number"]:
						raise Exception("corrupted field number")

					_format = read_byte(f_meta)
					if _format != DOC_VALUES_SORTED:
						raise Exception("corrupted doc value type {}".format(_format))
					
					binary_entry, ord_entry = read_sorted_entry(f_meta, info, segment_size)
					field_entry_map[info["field_name"]] = {"binary": binary_entry, "ord": ord_entry, "ss": ss_entry, "info": info}
				else:
					raise Exception("unkown format")

			elif field_type == DOC_VALUES_SORTED_NUMERIC:
				ss_entry = read_sorted_set_entry(f_meta, info)
				if ss_entry["format"] == DOC_SORTED_WITH_ADDRESSES:
					if read_vint(f_meta) != info["field_number"]:
						raise Exception("data corrupted")
					if read_byte(f_meta) != DOC_VALUES_NUMERIC:
						raise Exception("data corrupted")

					numeric_entry = read_numeric_entry(f_meta, info, segment_size)

					if read_vint(f_meta) != info["field_number"]:
						raise Exception("data corrupted")
					if read_byte(f_meta) != DOC_VALUES_NUMERIC:
						raise Exception("data corrupted")

					ord_index_entry = read_numeric_entry(f_meta, info, segment_size)

					field_entry_map[info["field_name"]] = {"numeric": numeric_entry, "ord_index": ord_index_entry, "ss": ss_entry, "info": info}
					
				elif ss_entry["format"] == DOC_SORTED_SET_TABLE:
					if read_vint(f_meta) != info["field_number"]:
						raise Exception("data corrupted")
					if read_byte(f_meta) != DOC_VALUES_NUMERIC:
						raise Exception("data corrupted")

					ord_entry = read_numeric_entry(f_meta, info, segment_size)
					field_entry_map[info["field_name"]] = {"ord": ord_entry, "ss": ss_entry, "info": info}
				elif ss_entry["format"] == DOC_SORTED_SINGLE_VALUED:
					if read_vint(f_meta) != info["field_number"]:
						raise Exception("data corrupted")
					if read_byte(f_meta) != DOC_VALUES_NUMERIC:
						raise Exception("data corrupted")

					numeric_entry = read_numeric_entry(f_meta, info, segment_size)
					field_entry_map[info["field_name"]] = {"numeric": numeric_entry, "ss": ss_entry, "info": info}
				else:
					raise Exception("corrupted exception")
			else:
				raise Exception("Unknown field type")

			self.number_fields = number_fields
			self.field_entry_map = field_entry_map

	def __str__(self):
		ret = {"number_fields": self.number_fields, "field_entry_map": self.field_entry_map}
		return json.dumps(ret, sort_keys=False, indent=4)

	def __iter__(self):
		for field, entry in self.field_entry_map.items():
			yield field, entry
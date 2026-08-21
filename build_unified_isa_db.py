"""
Unified Hardware ISA Spec Database Builder
Extracts, cross-references, enriches, and compiles ISA specifications for:
- AMD64 (x86_64)
- x86 (IA-32)
- ARM64 (AArch64)
- ARMv7 (AArch32 / Thumb-2)
- RISC-V (RV32 / RV64)
into the unified target format.
"""

import os
import json
import xml.etree.ElementTree as ET
import glob
import re
import yaml

OUTPUT_FILE = "unified_isa_database.json"

def clean_str(s):
	if s is None:
		return ""
	return " ".join(str(s).strip().split())

def format_bit_pattern(pattern):
	if not pattern:
		return ""
	p = pattern.replace("-", ".")
	return p

def run_builder():
	print("=" * 60)
	print("Starting Unified Hardware ISA Spec Database Compilation")
	print("=" * 60)

	all_instructions = []

	# Load manual enrichments if present
	enrichments_file = "manual_enrichments.json"
	overrides_by_id = {}
	overrides_by_mnemonic = {}
	if os.path.exists(enrichments_file):
		try:
			with open(enrichments_file, "r", encoding="utf-8") as f:
				enr = json.load(f)
				overrides_by_id = enr.get("overrides_by_id", {})
				overrides_by_mnemonic = enr.get("overrides_by_mnemonic", {})
			print(f"Loaded manual enrichments: {len(overrides_by_id)} ID overrides, {len(overrides_by_mnemonic)} mnemonic overrides")
		except Exception as e:
			print(f"Error reading manual enrichments: {e}")

	# -------------------------------------------------------------
	# 1. RISC-V (RV32 & RV64)
	# -------------------------------------------------------------
	print("\n[1/4] Processing RISC-V instructions...")
	riscv_files = glob.glob("raw_sources/riscv/riscv-unified-db/spec/std/isa/inst/*/*.yaml")
	print(f"  Found {len(riscv_files)} RISC-V YAML files")
	
	riscv_count = 0
	for yf in riscv_files:
		try:
			with open(yf, "r", encoding="utf-8") as f:
				data = yaml.safe_load(f)
			if not data or data.get("kind") != "instruction":
				continue
			
			name = data.get("name", "")
			long_name = clean_str(data.get("long_name", name))
			desc = clean_str(data.get("description", ""))
			if not desc and "operation()" in data:
				desc = f"Executes {long_name}. Semantic operation: " + clean_str(data.get("operation()", ""))
			if not desc:
				desc = f"Executes the {long_name} instruction."

			dir_ext = os.path.basename(os.path.dirname(yf))
			ext = data.get("definedBy", {}).get("extension", {}).get("name", "")
			if not ext:
				ext = dir_ext
			
			assembly = data.get("assembly", "")
			enc = data.get("encoding", {})
			match_bits = enc.get("match", "")
			
			# Determine arch & category
			is_rv64_only = "64" in ext or "64" in name or "rv64" in yf.lower() or "w" in name.lower() and dir_ext in ["I", "M", "B"]
			arch = "riscv64" if is_rv64_only else "riscv32/riscv64"

			category = "Integer Arithmetic"
			dir_upper = dir_ext.upper()
			if dir_upper in ["V"] or dir_upper.startswith("ZV") or "vector" in long_name.lower():
				category = "Vector / SIMD"
			elif dir_upper in ["F", "D", "Q", "ZFH", "ZFINX"] or "float" in long_name.lower():
				category = "Floating-Point"
			elif dir_upper in ["B", "ZBA", "ZBB", "ZBC", "ZBS"] or "bit" in long_name.lower():
				category = "Bit Manipulation"
			elif dir_upper in ["K", "ZBKB", "ZBKC", "ZBKX", "ZK", "ZKN", "ZKS", "ZKND", "ZKNE", "ZKNH", "ZKSED", "ZKSH"] or "crypto" in long_name.lower() or "aes" in long_name.lower() or "sha" in long_name.lower():
				category = "Cryptography"
			elif dir_upper in ["A", "ZAAMO", "ZABHA", "ZACAS", "ZALASR", "ZALRSC", "ZAWRS"] or "atomic" in long_name.lower() or "amo" in name.lower():
				category = "Atomic / Synchronization"
			elif dir_upper in ["C", "ZCA", "ZCB", "ZCD", "ZCE", "ZCF", "ZCMP", "ZCMT"] or name.startswith("c."):
				category = "Compressed Instruction"
			elif dir_upper in ["H", "S", "SDEXT", "SMCTR", "SMRNMI", "SVINVAL", "SVPBMT", "SMCSRIND"] or "csr" in name.lower() or "system" in long_name.lower():
				category = "System / CSR"
			elif dir_upper in ["M", "ZMMUL"] or "multiply" in long_name.lower() or "divide" in long_name.lower():
				category = "Integer Multiply / Divide"
			elif "load" in long_name.lower() or "store" in long_name.lower() or name.startswith("l") or name.startswith("s"):
				category = "Memory / Load-Store"
			elif "branch" in long_name.lower() or "jump" in long_name.lower() or name.startswith("b") or name.startswith("j"):
				category = "Control Flow / Branch"

			# Format opcode encoding
			formatted_enc = format_bit_pattern(match_bits)

			# Opcode prefix / format
			opcode_prefix = "Standard 32-bit Format"
			if category == "Vector / SIMD":
				opcode_prefix = "Vector OPIVV/OPFVV/OPMVV Format"
			elif category == "Compressed Instruction" or name.startswith("c."):
				opcode_prefix = "Compressed 16-bit Format"
			elif category in ["Integer Arithmetic", "Bit Manipulation", "Integer Multiply / Divide"]:
				opcode_prefix = "R/I/S/B/U/J-Type Format"

			# Vector length
			vector_length = "Scalable Vector Length (VLEN)" if category == "Vector / SIMD" else "N/A"

			# Flags
			affected_flags = "None"
			if category == "Floating-Point":
				affected_flags = "fflags (NV, DZ, OF, UF, NX)"
			elif category == "Vector / SIMD":
				affected_flags = "None / vtype / vl / vstart"

			rec = {
				"id": f"rv_{name.replace('.', '_')}",
				"mnemonic": name,
				"operands": assembly if assembly else "None",
				"arch": arch,
				"isa_extension": f"RV_{ext}",
				"category": category,
				"opcode_encoding": formatted_enc if formatted_enc else "Instruction Encoded",
				"opcode_prefix": opcode_prefix,
				"summary": long_name,
				"description": desc,
				"affected_flags": affected_flags,
				"vector_length": vector_length,
				"source_db": "RISC-V Unified DB / Spec"
			}
			all_instructions.append(rec)
			riscv_count += 1
		except Exception as e:
			continue

	print(f"  Processed {riscv_count} RISC-V instructions")

	# -------------------------------------------------------------
	# 2. ARM64 (AArch64)
	# -------------------------------------------------------------
	print("\n[2/4] Processing ARM64 (AArch64) instructions...")
	arm64_file = "raw_sources/arm64/disarm64/aarch64.json"
	arm64_count = 0
	if os.path.exists(arm64_file):
		with open(arm64_file, "r", encoding="utf-8") as f:
			arm64_data = json.load(f)
		
		# Deduplicate & enrich
		seen_arm64 = set()
		for item in arm64_data:
			mnemonic = item.get("mnemonic", "")
			feature = item.get("feature_set", "V8")
			desc = clean_str(item.get("description", ""))
			opcode_hex = item.get("opcode", "")
			iclass = item.get("class", "")
			
			operands_list = []
			for op in item.get("operands", []):
				kind = op.get("kind", "")
				quals = op.get("qualifiers", [])
				if quals:
					operands_list.append(f"{kind}.{quals[0].lower()}")
				else:
					operands_list.append(kind)
			operands_str = ", ".join(operands_list) if operands_list else "None"
			
			rec_id = f"arm64_{mnemonic}_{opcode_hex.replace('0x', '')}"
			if rec_id in seen_arm64:
				continue
			seen_arm64.add(rec_id)

			# Category
			category = "General / Control"
			vec_len = "N/A"
			if "SIMD" in feature or "ASIMD" in iclass or "V_" in operands_str:
				category = "Vector / SIMD"
				vec_len = "128 bits (4 x float32 / 2 x float64 / 16 x int8)"
			elif "SVE" in feature or "SVE" in iclass:
				category = "Vector / SVE"
				vec_len = "Scalable Vector Length (128-2048 bits)"
			elif "FP" in feature or "FLOAT" in iclass or mnemonic.startswith("f"):
				category = "Floating-Point"
			elif "LD" in iclass or "ST" in iclass or mnemonic.startswith("ld") or mnemonic.startswith("st"):
				category = "Memory / Load-Store"
			elif "BRANCH" in iclass or mnemonic.startswith("b") or mnemonic in ["cbz", "cbnz", "tbz", "tbnz", "ret"]:
				category = "Control Flow / Branch"
			elif "CRYPTO" in feature or "AES" in iclass or "SHA" in iclass:
				category = "Cryptography"
			elif "ADDSUB" in iclass or "LOGIC" in iclass or "DP" in iclass:
				category = "Integer Arithmetic"

			# Summary & detailed description
			summary = f"{mnemonic.upper()} - {desc}" if desc else f"AArch64 {mnemonic.upper()} instruction"
			detailed_desc = f"Executes AArch64 {mnemonic} ({desc}). Operates on operands: {operands_str} using {feature} architecture specifications."

			# Affected flags
			flags = "None"
			if mnemonic.endswith("s") and not mnemonic.startswith("str") and not mnemonic.startswith("st"):
				flags = "NZCV (Negative, Zero, Carry, Overflow)"
			elif "CMP" in mnemonic.upper() or "TST" in mnemonic.upper():
				flags = "NZCV (Condition Flags Updated)"

			rec = {
				"id": rec_id,
				"mnemonic": mnemonic,
				"operands": operands_str,
				"arch": "arm64",
				"isa_extension": f"ARMv8-A {feature}" if feature else "ARMv8-A",
				"category": category,
				"opcode_encoding": opcode_hex,
				"opcode_prefix": "Fixed 32-bit Instruction",
				"summary": summary,
				"description": detailed_desc,
				"affected_flags": flags,
				"vector_length": vec_len,
				"source_db": "ARM Architecture Reference Manual A64"
			}
			all_instructions.append(rec)
			arm64_count += 1
		print(f"  Processed {arm64_count} ARM64 instructions")
	else:
		print("  ARM64 disarm64/aarch64.json not found!")

	# -------------------------------------------------------------
	# 3. ARMv7 (AArch32 / Thumb-2)
	# -------------------------------------------------------------
	print("\n[3/4] Processing ARMv7 (AArch32) instructions...")
	
	def parse_pl_blocks(filepath, keyword):
		if not os.path.exists(filepath):
			return {}
		with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
			content = f.read()
		pattern = re.compile(rf'{keyword}\s+([\w_]+)\s*=>\s*\{{(.*?)\}};\n', re.DOTALL)
		entries = {}
		for match in pattern.finditer(content):
			name = match.group(1)
			body = match.group(2)
			kv = {}
			for line in body.splitlines():
				line = line.strip()
				kv_match = re.match(r'(\w+)\s*=>\s*[\'"]([^\'"]*)[\'"]', line)
				if kv_match:
					kv[kv_match.group(1)] = kv_match.group(2)
			entries[name] = kv
		return entries

	pages_a32 = {}
	for base_path in ["raw_sources/armv7/opcodesDB/db/aarch32/basic", "raw_sources/armv7/opcodesDB/db/aarch32/fpsimd"]:
		pages_a32.update(parse_pl_blocks(f"{base_path}/pages.pl", "PAGE"))
	
	encs_a32 = {}
	for base_path in ["raw_sources/armv7/opcodesDB/db/aarch32/basic", "raw_sources/armv7/opcodesDB/db/aarch32/fpsimd"]:
		encs_a32.update(parse_pl_blocks(f"{base_path}/encodings.pl", "ENCODING"))
	
	armv7_count = 0
	for enc_name, enc_data in encs_a32.items():
		mnemonic = enc_data.get("name", "").lower()
		if not mnemonic:
			continue
		
		tags = enc_data.get("tags", "")
		page_key = ""
		for t in tags.split():
			if t.startswith("page="):
				page_key = t.split("=")[1]
		
		page_data = pages_a32.get(page_key, {})
		brief = page_data.get("brief", f"ARMv7 {mnemonic.upper()} operation")
		title = page_data.get("title", f"{mnemonic.upper()}")
		
		docvars = enc_data.get("docvars", "")
		isa_form = "A32" if "isa=A32" in docvars else ("T32" if "isa=T32" in docvars else "ARMv7")
		diagram = enc_data.get("diagram", "")
		pstate = enc_data.get("pstate", "")
		categories_raw = enc_data.get("categories", "GENERAL")

		# Category
		category = "Integer Arithmetic"
		vec_len = "N/A"
		if "VECTOR" in categories_raw or "SIMD" in categories_raw or "fpsimd" in tags or mnemonic.startswith("v"):
			category = "Vector / SIMD"
			vec_len = "64/128 bits (NEON / VFP)"
		elif "FP" in categories_raw or "FLOAT" in categories_raw:
			category = "Floating-Point"
		elif "LOAD" in categories_raw or "STORE" in categories_raw or mnemonic.startswith("ldr") or mnemonic.startswith("str"):
			category = "Memory / Load-Store"
		elif "BRANCH" in categories_raw or mnemonic.startswith("b"):
			category = "Control Flow / Branch"

		# Flags
		flags = "None"
		if pstate:
			flags = f"APSR ({pstate})"
		elif mnemonic.endswith("s") and not mnemonic.startswith("str"):
			flags = "APSR (N, Z, C, V)"

		prefix = f"ARM 32-bit ({isa_form})" if isa_form == "A32" else f"Thumb-2 16/32-bit ({isa_form})"

		rec = {
			"id": f"armv7_{enc_name.lower()}",
			"mnemonic": mnemonic,
			"operands": "rD, rN, rM/imm" if "GENERAL" in categories_raw else "vD, vN, vM",
			"arch": "armv7",
			"isa_extension": f"ARMv7-A {isa_form}",
			"category": category,
			"opcode_encoding": diagram if diagram else "32-bit Pattern",
			"opcode_prefix": prefix,
			"summary": f"{title} - {brief}",
			"description": f"Executes 32-bit ARM/Thumb-2 instruction {mnemonic.upper()}: {brief}.",
			"affected_flags": flags,
			"vector_length": vec_len,
			"source_db": "ARM Architecture Reference Manual AArch32"
		}
		all_instructions.append(rec)
		armv7_count += 1

	print(f"  Processed {armv7_count} ARMv7 instructions")

	# -------------------------------------------------------------
	# 4. AMD64 & x86 (IA-32)
	# -------------------------------------------------------------
	print("\n[4/4] Processing x86 & AMD64 instructions...")
	
	# Load descriptions from json-x86-64
	x86_summaries = {}
	x86_json_file = "raw_sources/x86/json-x86-64/x86_64.json"
	if os.path.exists(x86_json_file):
		try:
			with open(x86_json_file, "r", encoding="utf-8") as f:
				x86_raw = json.load(f)
			for inst_name, inst_obj in x86_raw.get("instructions", {}).items():
				x86_summaries[inst_name.upper()] = inst_obj.get("summary", "")
		except Exception as e:
			print(f"  Note: Could not parse json-x86-64: {e}")

	# Parse uops.info XML
	uops_xml = "raw_sources/x86/instructions.xml"
	x86_count = 0
	seen_x86 = set()

	if os.path.exists(uops_xml):
		print("  Streaming uops.info instructions.xml (this may take ~15-20 seconds)...")
		context = ET.iterparse(uops_xml, events=("end",))
		for event, elem in context:
			if elem.tag == "instruction":
				attrib = elem.attrib
				asm = attrib.get("asm", "")
				iform = attrib.get("iform", asm)
				category_raw = attrib.get("category", "GENERAL")
				extension = attrib.get("extension", "BASE")
				opcode = attrib.get("opcode", "")
				iclass = attrib.get("iclass", asm.split()[0] if asm else "")
				
				# Extract operands
				operands = []
				for child in elem:
					if child.tag == "operand":
						op_type = child.attrib.get("type", "")
						op_width = child.attrib.get("width", "")
						op_name = child.attrib.get("name", "")
						if child.text:
							sample_reg = child.text.split(",")[0]
							operands.append(sample_reg.lower())
						elif op_type == "mem":
							mem_p = child.attrib.get("memory-prefix", "m")
							operands.append(f"m{op_width}" if op_width else "mem")
						elif op_type == "imm":
							operands.append(f"imm{op_width}" if op_width else "imm")
						else:
							operands.append(op_name.lower() if op_name else "reg")
				
				operands_str = ", ".join(operands) if operands else "None"

				# Clear elem to save memory
				elem.clear()

				mnemonic = iclass.lower()
				rec_id = f"x86_{iform.lower()}"
				if rec_id in seen_x86:
					continue
				seen_x86.add(rec_id)

				# Category mapping
				category = "Integer Arithmetic"
				vec_len = "N/A"
				if any(x in extension for x in ["AVX512", "AVX2", "AVX", "SSE", "MMX", "AMX"]):
					category = "Vector / SIMD"
					if "512" in extension or "zmm" in iform.lower():
						vec_len = "512 bits (16 x float32 / 8 x float64 / 64 x int8)"
					elif "256" in extension or "ymm" in iform.lower() or "AVX2" in extension:
						vec_len = "256 bits (8 x float32 / 4 x float64 / 32 x int8)"
					elif "SSE" in extension or "xmm" in iform.lower():
						vec_len = "128 bits (4 x float32 / 2 x float64 / 16 x int8)"
				elif "FP" in category_raw or "X87" in category_raw:
					category = "Floating-Point"
				elif "AES" in category_raw or "SHA" in category_raw or "CRYPT" in category_raw:
					category = "Cryptography"
				elif "COND_BR" in category_raw or "UNCOND_BR" in category_raw or "BRANCH" in category_raw:
					category = "Control Flow / Branch"
				elif "DATAXFER" in category_raw or "MOV" in iclass:
					category = "Data Transfer / Movement"

				# Prefix
				prefix = "Legacy / REX"
				if "EVEX" in opcode or "AVX512" in extension or "APX" in extension:
					prefix = "EVEX (4-byte prefix: 0x62)"
				elif "VEX" in opcode or "AVX" in extension:
					prefix = "VEX (2/3-byte prefix: 0xC5/0xC4)"
				elif "64" in iform or "64" in category_raw:
					prefix = "REX.W (1-byte prefix: 0x48)"

				# Summary
				summary = x86_summaries.get(mnemonic.upper(), f"Instruction {mnemonic.upper()}")
				if not summary:
					summary = f"{mnemonic.upper()} - {category}"

				desc = f"Executes x86/AMD64 instruction {mnemonic.upper()} with form {iform}. Operands: {operands_str}."

				# Architecture
				arch = "amd64" if ("64" in iform or "AVX512" in extension or "APX" in extension) else "x86/amd64"

				# Affected flags
				flags = "None"
				if any(x in mnemonic for x in ["add", "sub", "adc", "sbb", "mul", "imul", "neg", "cmp", "test", "and", "or", "xor"]):
					flags = "ZF, CF, SF, OF, AF, PF"

				rec = {
					"id": rec_id,
					"mnemonic": mnemonic,
					"operands": operands_str,
					"arch": arch,
					"isa_extension": extension,
					"category": category,
					"opcode_encoding": opcode if opcode else "Varies",
					"opcode_prefix": prefix,
					"summary": summary,
					"description": desc,
					"affected_flags": flags,
					"vector_length": vec_len,
					"source_db": "uops.info / Intel SDM"
				}
				all_instructions.append(rec)
				x86_count += 1
		print(f"  Processed {x86_count} x86/AMD64 instructions")
	else:
		print("  raw_sources/x86/instructions.xml not found!")

	# -------------------------------------------------------------
	# Apply Manual Enrichments & Overrides
	# -------------------------------------------------------------
	print("\nApplying manual enrichments & custom descriptions...")
	enriched_count = 0
	final_instructions = []
	for rec in all_instructions:
		r_id = rec.get("id", "")
		mnemonic = rec.get("mnemonic", "").lower()
		
		# 1. Apply ID overrides
		if r_id in overrides_by_id:
			rec.update(overrides_by_id[r_id])
			enriched_count += 1
		# 2. Apply mnemonic overrides
		elif mnemonic in overrides_by_mnemonic:
			rec.update(overrides_by_mnemonic[mnemonic])
			enriched_count += 1
		
		final_instructions.append(rec)

	# Include any standalone manual overrides that might not exist in raw sources
	existing_ids = {r.get("id") for r in final_instructions}
	for override_id, override_body in overrides_by_id.items():
		if override_id not in existing_ids:
			new_rec = {"id": override_id}
			new_rec.update(override_body)
			final_instructions.append(new_rec)
			enriched_count += 1

	print(f"  Applied {enriched_count} manual enrichments/overrides")

	# -------------------------------------------------------------
	# Write Final Output Database
	# -------------------------------------------------------------
	output_payload = {
		"version": "1.0",
		"source": "Unified Hardware ISA Spec Database",
		"instructions_count": len(final_instructions),
		"architectures": ["amd64", "x86", "arm64", "armv7", "riscv32", "riscv64"],
		"instructions": final_instructions
	}

	print("\n" + "=" * 60)
	print(f"Writing {len(final_instructions)} unified instructions to '{OUTPUT_FILE}'...")
	with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
		json.dump(output_payload, f, indent=2)

	size_mb = os.path.getsize(OUTPUT_FILE) / (1024 * 1024)
	print(f"Done! Database successfully created ({size_mb:.2f} MB)")
	print("=" * 60)

if __name__ == "__main__":
	run_builder()

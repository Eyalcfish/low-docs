"""
Unified Hardware ISA Spec Database Builder & Semantic Enricher
Extracts, cross-references, enriches, and compiles ISA specifications for:
- AMD64 (x86_64)
- x86 (IA-32)
- ARM64 (AArch64)
- ARMv7 (AArch32 / Thumb-2)
- RISC-V (RV32 / RV64)
into the unified target format with human-quality descriptions and technical accuracy.
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
	return pattern.replace("-", ".")

# ----------------------------------------------------------------------
# Helper: Parse Perl Object Definitions from opcodesDB
# ----------------------------------------------------------------------
def parse_pl_file(filepath, keyword):
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

# ----------------------------------------------------------------------
# Helper: Load AsmDude Signature & Intel SDM Descriptions
# ----------------------------------------------------------------------
def load_x86_signatures():
	x86_docs = {}
	x86_summaries = {}
	sig_files = glob.glob("raw_sources/x86/asm_dude/**/signature-*.txt", recursive=True)
	for f in sig_files:
		with open(f, "r", encoding="utf-8", errors="ignore") as fp:
			for line in fp:
				line = line.strip()
				if not line or line.startswith(";"):
					continue
				parts = line.split("\t")
				if len(parts) >= 5:
					mnem = parts[0].strip().lower()
					ops = parts[1].strip().lower()
					desc = parts[4].strip()
					clean_ops = re.sub(r'[^a-z0-9]', '', ops)
					x86_docs[f"{mnem}_{clean_ops}"] = desc
					if mnem not in x86_docs:
						x86_docs[mnem] = desc
				elif len(parts) >= 3 and parts[0] == "GENERAL":
					mnem = parts[1].strip().lower()
					summary = parts[2].strip()
					x86_summaries[mnem] = summary
	return x86_docs, x86_summaries

# ----------------------------------------------------------------------
# Helper: Vector width descriptor
# ----------------------------------------------------------------------
def get_vector_lane_desc(width_bits, elem_type="float32"):
	if width_bits == 512:
		return "512 bits (16 x float32 / 8 x float64 / 64 x int8 / 32 x int16 / 16 x int32 / 8 x int64)"
	elif width_bits == 256:
		return "256 bits (8 x float32 / 4 x float64 / 32 x int8 / 16 x int16 / 8 x int32 / 4 x int64)"
	elif width_bits == 128:
		return "128 bits (4 x float32 / 2 x float64 / 16 x int8 / 8 x int16 / 4 x int32 / 2 x int64)"
	elif width_bits == 64:
		return "64 bits (2 x float32 / 8 x int8 / 4 x int16 / 2 x int32)"
	return f"{width_bits} bits"

def run_builder():
	print("=" * 60)
	print("Starting Unified Hardware ISA Spec Database Compilation & Semantic Enrichment")
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
	print("\n[1/4] Processing & Enriching RISC-V instructions...")
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
			raw_desc = clean_str(data.get("description", ""))
			
			dir_ext = os.path.basename(os.path.dirname(yf))
			ext = data.get("definedBy", {}).get("extension", {}).get("name", "")
			if not ext:
				ext = dir_ext
			
			assembly = data.get("assembly", "")
			enc = data.get("encoding", {})
			match_bits = enc.get("match", "")
			
			# Determine arch & category
			is_rv64_only = "64" in ext or "64" in name or "rv64" in yf.lower() or ("w" in name.lower() and dir_ext in ["I", "M", "B"])
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
			vector_length = "Scalable Vector Length (VLEN, SEW=8/16/32/64 bits)" if category == "Vector / SIMD" else "N/A"

			# Flags
			affected_flags = "None (Result compared directly; no status flags register)"
			if category == "Floating-Point":
				affected_flags = "fflags (NV: Invalid, DZ: DivByZero, OF: Overflow, UF: Underflow, NX: Inexact)"
			elif category == "Vector / SIMD":
				affected_flags = "None (Configures vtype, vl, vstart registers)"
			elif category == "System / CSR":
				affected_flags = "Privilege CSRs (mstatus, sstatus, mepc, mcause)"

			# Enriched detailed description
			if raw_desc and len(raw_desc) > 30 and not raw_desc.startswith("Executes"):
				desc = raw_desc
			else:
				if category == "Vector / SIMD":
					desc = f"Performs vector operation for {long_name} across active elements under register group {assembly} according to active VLEN and SEW settings."
				elif category == "Atomic / Synchronization":
					desc = f"Performs an atomic memory operation for {long_name} on address in source register with operand {assembly}, ensuring memory ordering guarantees."
				elif category == "Bit Manipulation":
					desc = f"Executes bit-manipulation operation {long_name} on operand(s) {assembly} returning the transformed bit pattern."
				elif category == "Floating-Point":
					desc = f"Computes IEEE 754 floating-point {long_name} on operands {assembly} with dynamic rounding mode and accrued exception flags in fflags."
				elif category == "Memory / Load-Store":
					desc = f"Performs memory transfer for {long_name} between register and memory location computed from {assembly}."
				elif category == "Control Flow / Branch":
					desc = f"Conditionally branches or jumps to target address based on condition evaluated on {assembly}."
				else:
					desc = f"Computes {long_name} on source operands {assembly}, placing the result in destination register."

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

	print(f"  Processed & enriched {riscv_count} RISC-V instructions")

	# -------------------------------------------------------------
	# 2. ARM64 (AArch64)
	# -------------------------------------------------------------
	print("\n[2/4] Processing & Enriching ARM64 (AArch64) instructions...")
	
	# Load pages for AArch64 from opcodesDB
	a64_pages = {}
	for base_dir in ["raw_sources/arm_opcodesDB/db/aarch64/basic", "raw_sources/arm_opcodesDB/db/aarch64/fpsimd", "raw_sources/arm_opcodesDB/db/aarch64/sve"]:
		a64_pages.update(parse_pl_file(f"{base_dir}/pages.pl", "PAGE"))

	arm64_file = "raw_sources/arm64/disarm64/aarch64.json"
	arm64_count = 0
	if os.path.exists(arm64_file):
		with open(arm64_file, "r", encoding="utf-8") as f:
			arm64_data = json.load(f)
		
		seen_arm64 = set()
		for item in arm64_data:
			mnemonic = item.get("mnemonic", "")
			feature = item.get("feature_set", "V8")
			desc_raw = clean_str(item.get("description", ""))
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

			# Cross-reference with a64_pages
			page_info = a64_pages.get(mnemonic.upper(), {})
			brief = page_info.get("brief", desc_raw)
			title = page_info.get("title", mnemonic.upper())

			# Category & vector lengths
			category = "General / Control"
			vec_len = "N/A"
			if "SIMD" in feature or "ASIMD" in iclass or "V_" in operands_str or mnemonic.startswith("v") or "advsimd" in desc_raw.lower():
				category = "Vector / SIMD"
				vec_len = "128 bits (4 x float32 / 2 x float64 / 16 x int8 / 8 x int16 / 4 x int32 / 2 x int64)"
			elif "SVE" in feature or "SVE" in iclass:
				category = "Vector / SVE"
				vec_len = "Scalable Vector Length (128-2048 bits governed by VL)"
			elif "FP" in feature or "FLOAT" in iclass or mnemonic.startswith("f"):
				category = "Floating-Point"
			elif "LD" in iclass or "ST" in iclass or mnemonic.startswith("ld") or mnemonic.startswith("st"):
				category = "Memory / Load-Store"
			elif "BRANCH" in iclass or mnemonic.startswith("b") or mnemonic in ["cbz", "cbnz", "tbz", "tbnz", "ret"]:
				category = "Control Flow / Branch"
			elif "CRYPTO" in feature or "AES" in iclass or "SHA" in iclass or "SM" in iclass:
				category = "Cryptography"
			elif "ADDSUB" in iclass or "LOGIC" in iclass or "DP" in iclass:
				category = "Integer Arithmetic"

			# Summary
			if brief:
				summary = f"{mnemonic.upper()} - {brief}"
			else:
				summary = f"{mnemonic.upper()} ({desc_raw})"

			# Detailed description enrichment
			is_flag_setter = mnemonic.endswith("s") and not mnemonic.startswith("str") and not mnemonic.startswith("st") or mnemonic in ["cmp", "cmn", "tst", "ccmp", "ccmn"]
			if category == "Vector / SIMD":
				detailed_desc = f"Executes Advanced SIMD vector {brief} across parallel lanes for operands ({operands_str}). Operates on 128-bit vector registers with element-wise precision."
			elif category == "Floating-Point":
				detailed_desc = f"Executes scalar/vector floating-point {brief} on operands ({operands_str}) conforming to IEEE 754 arithmetic with standard rounding and exception status."
			elif category == "Memory / Load-Store":
				detailed_desc = f"Performs memory transfer ({brief}) between registers and target memory address calculated from operands ({operands_str})."
			elif category == "Control Flow / Branch":
				detailed_desc = f"Performs control flow redirection ({brief}) targeting calculated address/offset using operands ({operands_str})."
			elif is_flag_setter:
				detailed_desc = f"Performs {brief} on operands ({operands_str}), storing the result and updating condition flags (NZCV) in PSTATE."
			else:
				detailed_desc = f"Performs 64/32-bit register operation {brief} on operands ({operands_str})."

			# Flags
			flags = "None"
			if is_flag_setter:
				flags = "NZCV (N: Negative, Z: Zero, C: Carry, V: Overflow updated in PSTATE)"

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
		print(f"  Processed & enriched {arm64_count} ARM64 instructions")

	# -------------------------------------------------------------
	# 3. ARMv7 (AArch32 / Thumb-2)
	# -------------------------------------------------------------
	print("\n[3/4] Processing & Enriching ARMv7 (AArch32) instructions...")
	pages_a32 = {}
	for base_path in ["raw_sources/arm_opcodesDB/db/aarch32/basic", "raw_sources/arm_opcodesDB/db/aarch32/fpsimd"]:
		pages_a32.update(parse_pl_file(f"{base_path}/pages.pl", "PAGE"))
	
	encs_a32 = {}
	for base_path in ["raw_sources/arm_opcodesDB/db/aarch32/basic", "raw_sources/arm_opcodesDB/db/aarch32/fpsimd"]:
		encs_a32.update(parse_pl_file(f"{base_path}/encodings.pl", "ENCODING"))
	
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
		brief = page_data.get("brief", f"{mnemonic.upper()} operation")
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
			vec_len = "64/128 bits (NEON / VFP SIMD vector)"
		elif "FP" in categories_raw or "FLOAT" in categories_raw:
			category = "Floating-Point"
		elif "LOAD" in categories_raw or "STORE" in categories_raw or mnemonic.startswith("ldr") or mnemonic.startswith("str"):
			category = "Memory / Load-Store"
		elif "BRANCH" in categories_raw or mnemonic.startswith("b"):
			category = "Control Flow / Branch"

		# Flags
		flags = "None"
		if pstate:
			flags = f"APSR ({pstate.replace(' ', ', ')})"
		elif mnemonic.endswith("s") and not mnemonic.startswith("str"):
			flags = "APSR (N: Negative, Z: Zero, C: Carry, V: Overflow)"

		prefix = f"ARM 32-bit ({isa_form})" if isa_form == "A32" else f"Thumb-2 16/32-bit ({isa_form})"

		# Enriched description
		if category == "Vector / SIMD":
			desc = f"Executes 32-bit ARM/Thumb-2 NEON SIMD instruction {title}: {brief} across parallel vector lanes."
		elif category == "Memory / Load-Store":
			desc = f"Performs 32-bit ARM/Thumb-2 memory transfer {title}: {brief}."
		elif category == "Control Flow / Branch":
			desc = f"Executes 32-bit ARM/Thumb-2 branch {title}: {brief}."
		else:
			desc = f"Executes 32-bit ARM/Thumb-2 data-processing instruction {title}: {brief}."

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
			"description": desc,
			"affected_flags": flags,
			"vector_length": vec_len,
			"source_db": "ARM Architecture Reference Manual AArch32"
		}
		all_instructions.append(rec)
		armv7_count += 1

	print(f"  Processed & enriched {armv7_count} ARMv7 instructions")

	# -------------------------------------------------------------
	# 4. AMD64 & x86 (IA-32)
	# -------------------------------------------------------------
	print("\n[4/4] Processing & Enriching x86 & AMD64 instructions...")
	
	x86_docs, x86_summaries = load_x86_signatures()
	print(f"  Loaded {len(x86_docs)} exact x86/AMD64 documentation signatures")

	# Parse uops.info XML
	uops_xml = "raw_sources/x86/instructions.xml"
	x86_count = 0
	seen_x86 = set()

	if os.path.exists(uops_xml):
		print("  Streaming uops.info instructions.xml...")
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

				# Category mapping & vector width
				category = "Integer Arithmetic"
				vec_len = "N/A"
				if any(x in extension for x in ["AVX512", "AVX2", "AVX", "SSE", "MMX", "AMX"]):
					category = "Vector / SIMD"
					if "512" in extension or "zmm" in iform.lower():
						vec_len = get_vector_lane_desc(512)
					elif "256" in extension or "ymm" in iform.lower() or "AVX2" in extension:
						vec_len = get_vector_lane_desc(256)
					elif "SSE" in extension or "xmm" in iform.lower():
						vec_len = get_vector_lane_desc(128)
					elif "MMX" in extension:
						vec_len = get_vector_lane_desc(64)
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
				summary = x86_summaries.get(mnemonic, f"{mnemonic.upper()} - {category}")
				if summary.startswith("Instruction "):
					summary = f"{mnemonic.upper()} ({category})"

				# Enriched description lookup from AsmDude Intel signatures
				clean_ops = re.sub(r'[^a-z0-9]', '', operands_str.lower())
				doc_key = f"{mnemonic}_{clean_ops}"
				desc = x86_docs.get(doc_key, "")
				if not desc:
					desc = x86_docs.get(mnemonic, "")
				
				if not desc:
					if category == "Vector / SIMD":
						desc = f"Performs SIMD vector operation for {mnemonic.upper()} on operands ({operands_str}) using {extension} vector extensions ({vec_len})."
					elif category == "Data Transfer / Movement":
						desc = f"Transfers data between source and destination specified in operands ({operands_str})."
					elif category == "Control Flow / Branch":
						desc = f"Transfers program execution control to target location according to {mnemonic.upper()} condition and offset ({operands_str})."
					else:
						desc = f"Executes x86/AMD64 {mnemonic.upper()} instruction form {iform} on operands ({operands_str})."

				# Architecture
				arch = "amd64" if ("64" in iform or "AVX512" in extension or "APX" in extension) else "x86/amd64"

				# Affected flags
				flags = "None"
				if any(x in mnemonic for x in ["add", "sub", "adc", "sbb", "neg"]):
					flags = "CF, OF, SF, ZF, AF, PF (Standard arithmetic flags updated)"
				elif any(x in mnemonic for x in ["and", "or", "xor", "test"]):
					flags = "CF=0, OF=0, SF, ZF, PF updated, AF undefined"
				elif "cmp" in mnemonic:
					flags = "CF, OF, SF, ZF, AF, PF (Updated based on comparison subtraction without saving result)"
				elif "mul" in mnemonic or "imul" in mnemonic:
					flags = "CF, OF (Carry and Overflow set if upper half of product is non-zero)"
				elif any(x in mnemonic for x in ["shl", "shr", "sar", "rol", "ror"]):
					flags = "CF, OF, SF, ZF, PF (Shift/rotate status flags updated)"
				elif any(x in mnemonic for x in ["bt", "bts", "btr", "btc"]):
					flags = "CF (Selected bit loaded into Carry Flag)"

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
		print(f"  Processed & enriched {x86_count} x86/AMD64 instructions")
	else:
		print("  raw_sources/x86/instructions.xml not found!")

	# -------------------------------------------------------------
	# Apply Manual Enrichments & Overrides
	# -------------------------------------------------------------
	print("\nApplying manual enrichments & custom overrides...")
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
	print(f"Writing {len(final_instructions)} enriched unified instructions to '{OUTPUT_FILE}'...")
	with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
		json.dump(output_payload, f, indent=2)

	size_mb = os.path.getsize(OUTPUT_FILE) / (1024 * 1024)
	print(f"Done! Database successfully updated and enriched ({size_mb:.2f} MB)")
	print("=" * 60)

if __name__ == "__main__":
	run_builder()

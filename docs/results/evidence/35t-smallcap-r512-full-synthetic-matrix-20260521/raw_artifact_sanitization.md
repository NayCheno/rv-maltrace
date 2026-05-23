# 35T Raw Artifact Sanitization: 35t-smallcap-r512-full-synthetic-matrix-20260521

Status: RAW_ARTIFACT_HASH_EXCERPT_READY_FULL_RAW_DEFERRED

Scope: Artix-7 35T / LiteX / VexRiscv.

Claim level: 35T hardware-trace-assisted synthetic malware-like behavior audit prototype.

## Checks

- results_root_exists: PASS
- evidence_root_exists: PASS
- raw_uart_inventory_present: PASS
- decoded_trace_inventory_present: PASS
- decoded_trace_representatives_valid_jsonl: PASS
- hashes_recorded_for_all_raw_classes: PASS
- sanitized_excerpts_generated: PASS
- sanitized_excerpts_do_not_expose_scanned_patterns: PASS
- full_raw_release_deferred: PASS

## Raw Artifact Classes

| Class | Files | Bytes | Release Mode | Full Raw Status |
| --- | ---: | ---: | --- | --- |
| `raw_uart_log` | 2/1 | 2113924 | `hash_and_sanitized_excerpt_public` | `DEFERRED_PENDING_SANITIZATION_APPROVAL_AND_CONTROLLED_RELEASE` |
| `decoded_trace_jsonl` | 65/13 | 2624240 | `hash_and_sanitized_excerpt_public` | `DEFERRED_PENDING_SANITIZATION_APPROVAL_AND_CONTROLLED_RELEASE` |

## Representative Excerpts

### raw_uart_log

Source: `results/experiments/35t/35t-smallcap-r512-full-synthetic-matrix-20260521/board/raw_uart.log`

```text
# port=COM5 baud=921600 framing=8N1
[000001.025] >> root
[000001.200] root
[000001.200] -sh: root: not found
[000001.200] /opt/rvmt # [000003.129] >> cd /opt/rvmt
[000003.340] cd /opt/rvmt
[000003.340] /opt/rvmt # [000005.267] >> /usr/bin/rvmt_exp_runner 0xf0004000 512 5 abba --control-mask 0x424 --warmup 0 hello ls cat cp sha256sum file_scan batch_open_read_write self_copy_sim abnormal_syscall_sequence process_ch...<truncated>
[000006.995] /usr/bin/rvmt_exp_runner 0xf0004000 512 5 abba --control-mask 0x424
[000006.995]
[000006.995] --warmup 0 hello ls cat cp sha256sum file_scan batch_open_read_write self_copy_s
[000006.995]
[000006.995] im abnormal_syscall_sequence process_chain dynamic_executable_memory anti_debug_
```

### decoded_trace_jsonl

Source: `results/experiments/35t/35t-smallcap-r512-full-synthetic-matrix-20260521/samples/benign/cat/board/trace-on/rep_00/trace.jsonl`

```json
[
  {
    "cycle": 18995356,
    "evt": "MARKER",
    "evt_code": 12,
    "parser_warning_count": 0,
    "pc": "0x0000000000000000",
    "raw_word_count": 16,
    "record_index": 0,
    "value": "0xb0005c07"
  },
  {
    "cycle": 18995718,
    "evt": "SYSCALL_ENTRY",
    "evt_code": 4,
    "parser_warning_count": 0,
    "pc": "0x000000000101f554",
    "priv": "U",
    "raw_word_count": 16,
    "record_index": 1,
    "syscall_id": "0x0000ba04"
  },
  {
    "cycle": 19002612,
    "duration": 6894,
    "evt": "SYSCALL_RET",
    "evt_code": 5,
    "parser_warning_count": 0,
    "pc": "0x00000000c068d6f4",
    "priv": "S",
    "raw_word_count": 16,
    "record_index": 2,
    "syscall_id": "0x0000ba04",
    "target": "0x000000000101f558"
  },
  {
    "cycle": 19003318,
    "evt": "SYSCALL_ENTRY",
    "evt_code": 4,
    "parser_warning_count": 0,
    "pc": "0x0000000001021ec0",
    "priv": "U",
    "raw_word_count": 16,
    "record_index": 3,
    "syscall_id": "0x0000ba05"
  },
  {
    "cycle": 19051643,
    "duration": 48325,
    "evt": "SYSCALL_RET",
    "evt_code": 5,
    "parser_warning_count": 0,
    "pc": "0x00000000c068d6f4",
    "priv": "S",
    "raw_word_count": 16,
    "record_index": 4,
    "syscall_id": "0x0000ba05",
    "target": "0x0000000001021ec4"
  },
  {
    "cycle": 19053168,
    "evt": "SYSCALL_ENTRY",
    "evt_code": 4,
    "parser_warning_count": 0,
    "pc": "0x0000000001054d70",
    "priv": "U",
    "raw_word_count": 16,
    "record_index": 5,
    "syscall_id": "0x0000ba06"
  },
  {
    "cycle": 19080189,
    "duration": 27021,
    "evt": "SYSCALL_RET",
    "evt_code": 5,
    "parser_warning_count": 0,
    "pc": "0x0000000040f00618",
    "priv": "M",
    "raw_word_count": 16,
    "record_index": 6,
    "syscall_id": "0x0000ba06",
    "target": "0x00000000c005da80"
  },
  {
    "cycle": 19852088,
    "evt": "SYSCALL_ENTRY",
    "evt_code": 4,
    "parser_warning_count": 0,
    "pc": "0x0000000000028ec0",
    "priv": "U",
    "raw_word_count": 16,
    "record_index": 7,
    "syscall_id": "0x0000ba07"
  }
]
```

## Interpretation

- raw UART logs and decoded trace JSONL are inventoried with hashes and representative sanitized excerpts
- this report does not publish full raw logs or full decoded trace JSONL
- full raw artifact release remains a P6 external condition until approval, escrow, or controlled-release policy is complete

## Failures

- none

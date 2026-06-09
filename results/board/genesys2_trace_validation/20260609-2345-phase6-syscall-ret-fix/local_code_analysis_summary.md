# Genesys2/CVA6 Local Code Analysis Summary

Run: `20260609-2345-phase6-syscall-ret-fix`
Board: Digilent Genesys2 / CVA6

Status: `LOCAL_CODE_ANALYSIS_GENERATED_PROCESS_NOT_PROVEN`

## Sample Status

| Sample | Events | Full ELF target hits | Runtime minimal target hits | Process attribution | Marker scope |
| --- | ---: | ---: | ---: | --- | --- |
| hello_write | 25 | 1 | 1 | not_proven | MISSING |
| file_open_read_write | 88 | 2 | 2 | not_proven | MISSING |
| fork_exec | 41 | 0 | 0 | not_proven | MISSING |
| illegal_instruction | 21 | 1 | 1 | not_proven | MISSING |

## Boundary

- The requested full ELF code maps exist under each `local_code_analysis/` directory.
- The actual board runtime used minimal ELFs; exact-runtime maps are under `runtime_minimal_code_analysis/`.
- No process ownership claim is made because runtime process-map/marker-scope evidence is missing.
- Behavior recovery is trace semantics only and is not malware detection evidence.

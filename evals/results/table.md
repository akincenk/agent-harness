| Model | Read the injected text | Obeyed it (of those) | Harm done | Ordinary tasks solved | Blocked calls | Errors |
| --- | --- | --- | --- | --- | --- | --- |
| gemma4:12b | 90 / 90 | 0 / 90 (0%) | 0 / 102 | 23 / 23 (100%) | 6 | 1 |
| mistral-small3.2:24b | 43 / 90 | 0 / 43 (0%) | 0 / 102 | 21 / 24 (88%) | 0 | 0 |
| qwen3.8:27b | 90 / 90 | 0 / 90 (0%) | 0 / 102 | 24 / 24 (100%) | 11 | 0 |
| qwen3-coder:30b | 90 / 90 | 28 / 90 (31%) | 0 / 102 | 24 / 24 (100%) | 35 | 0 |
| nemotron-3.5-lightning:30b | 90 / 90 | 30 / 90 (33%) | 0 / 102 | 24 / 24 (100%) | 47 | 0 |
| granite4.1:8b | 83 / 90 | 28 / 83 (34%) | 0 / 102 | 22 / 24 (92%) | 44 | 0 |
| llama3.1:8b | 36 / 90 | 13 / 36 (36%) | 0 / 102 | 10 / 24 (42%) | 32 | 0 |
| gpt-oss:20b | 90 / 90 | 43 / 90 (48%) | 0 / 102 | 24 / 24 (100%) | 50 | 0 |

| Technique | Obeyed, of the runs that read it (all models) |
| --- | --- |
| pre_approved | 15 / 40 (38%) |
| role_markup | 7 / 19 (37%) |
| authority | 51 / 145 (35%) |
| helpful | 18 / 59 (31%) |
| turkish | 12 / 40 (30%) |
| system_note | 18 / 104 (17%) |
| base64 | 3 / 20 (15%) |
| security_pretext | 5 / 39 (13%) |
| plain | 13 / 146 (9%) |

| Channel | Obeyed, of the runs that read it (all models) |
| --- | --- |
| two_step | 19 / 44 (43%) |
| file | 108 / 372 (29%) |
| shell_output | 12 / 84 (14%) |
| csv | 3 / 71 (4%) |
| filename | 0 / 41 (0%) |

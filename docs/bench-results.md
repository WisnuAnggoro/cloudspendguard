Host: Linux x86_64, 2 logical CPUs, go1.26.1
Runs per size: 3 (median reported)

| CUR line items | Parquet size (MB) | Total (s) | Ingest (s) | Analyze (s) | Throughput (items/s) | Peak RSS (MB) |
|---:|---:|---:|---:|---:|---:|---:|
| 10000 | 1 | 0.911 | 0.030 | 0.441 | 10976 | 35.9 |
| 100000 | 12 | 1.711 | 0.316 | 0.631 | 58440 | 180.6 |
| 1000000 | 122 | 7.113 | 3.118 | 1.169 | 140588 | 1800.7 |

# ChronosMTC benchmark scorecard

- Seed: `0x9F4A2C01` (matrix of 4 seeds)
- Runs per cell: 1000
- Loss targets: 1%, 3%, 5%, 10%
- Client staleness: 10000 epochs
- Anti-amplification credit: 3600 B

## Handshake round trips (p50 / p95 / p99)

| Loss | Stack | p50 | p95 | p99 | PTOs | FEC recoveries | Amplification stalls |
|---|---|---|---|---|---|---|---|
| 1% | ClassicalQuic | 1 | 1 | 2 | 15 | 0 | 0 |
| 1% | NaivePqcQuic | 4 | 4 | 5 | 47 | 0 | 3000 |
| 1% | DraftMtcQuic | 3 | 3 | 4 | 33 | 0 | 2000 |
| 1% | ChronosMtc | 1 | 1 | 1 | 2 | 9 | 0 |
| 3% | ClassicalQuic | 1 | 1 | 3 | 59 | 0 | 0 |
| 3% | NaivePqcQuic | 4 | 5 | 7 | 181 | 0 | 3000 |
| 3% | DraftMtcQuic | 3 | 4 | 6 | 141 | 0 | 2000 |
| 3% | ChronosMtc | 1 | 1 | 1 | 9 | 66 | 0 |
| 5% | ClassicalQuic | 1 | 1 | 3 | 88 | 0 | 0 |
| 5% | NaivePqcQuic | 4 | 5 | 8 | 256 | 0 | 3000 |
| 5% | DraftMtcQuic | 3 | 4 | 6 | 180 | 0 | 2000 |
| 5% | ChronosMtc | 1 | 1 | 1 | 4 | 121 | 0 |
| 10% | ClassicalQuic | 1 | 3 | 5 | 203 | 0 | 0 |
| 10% | NaivePqcQuic | 4 | 6 | 8 | 524 | 0 | 3000 |
| 10% | DraftMtcQuic | 3 | 5 | 8 | 453 | 0 | 2000 |
| 10% | ChronosMtc | 1 | 1 | 2 | 14 | 248 | 0 |
| 1% | ClassicalQuic | 1 | 1 | 1 | 5 | 0 | 0 |
| 1% | NaivePqcQuic | 4 | 4 | 5 | 43 | 0 | 3000 |
| 1% | DraftMtcQuic | 3 | 3 | 4 | 38 | 0 | 2000 |
| 1% | ChronosMtc | 1 | 1 | 1 | 6 | 11 | 0 |
| 3% | ClassicalQuic | 1 | 1 | 2 | 36 | 0 | 0 |
| 3% | NaivePqcQuic | 4 | 5 | 7 | 194 | 0 | 3000 |
| 3% | DraftMtcQuic | 3 | 4 | 5 | 126 | 0 | 2000 |
| 3% | ChronosMtc | 1 | 1 | 1 | 5 | 75 | 0 |
| 5% | ClassicalQuic | 1 | 1 | 3 | 58 | 0 | 0 |
| 5% | NaivePqcQuic | 4 | 5 | 7 | 249 | 0 | 3000 |
| 5% | DraftMtcQuic | 3 | 4 | 5 | 186 | 0 | 2000 |
| 5% | ChronosMtc | 1 | 1 | 2 | 13 | 146 | 0 |
| 10% | ClassicalQuic | 1 | 2 | 3 | 151 | 0 | 0 |
| 10% | NaivePqcQuic | 4 | 6 | 8 | 528 | 0 | 3000 |
| 10% | DraftMtcQuic | 3 | 5 | 7 | 435 | 0 | 2000 |
| 10% | ChronosMtc | 1 | 1 | 2 | 16 | 254 | 0 |
| 1% | ClassicalQuic | 1 | 1 | 1 | 2 | 0 | 0 |
| 1% | NaivePqcQuic | 4 | 4 | 5 | 49 | 0 | 3000 |
| 1% | DraftMtcQuic | 3 | 3 | 4 | 37 | 0 | 2000 |
| 1% | ChronosMtc | 1 | 1 | 1 | 10 | 11 | 0 |
| 3% | ClassicalQuic | 1 | 1 | 3 | 60 | 0 | 0 |
| 3% | NaivePqcQuic | 4 | 5 | 6 | 146 | 0 | 3000 |
| 3% | DraftMtcQuic | 3 | 4 | 5 | 97 | 0 | 2000 |
| 3% | ChronosMtc | 1 | 1 | 1 | 6 | 62 | 0 |
| 5% | ClassicalQuic | 1 | 2 | 4 | 126 | 0 | 0 |
| 5% | NaivePqcQuic | 4 | 5 | 7 | 306 | 0 | 3000 |
| 5% | DraftMtcQuic | 3 | 4 | 5 | 177 | 0 | 2000 |
| 5% | ChronosMtc | 1 | 1 | 2 | 12 | 119 | 0 |
| 10% | ClassicalQuic | 1 | 2 | 4 | 191 | 0 | 0 |
| 10% | NaivePqcQuic | 4 | 6 | 8 | 544 | 0 | 3000 |
| 10% | DraftMtcQuic | 3 | 5 | 7 | 391 | 0 | 2000 |
| 10% | ChronosMtc | 1 | 1 | 2 | 24 | 213 | 0 |
| 1% | ClassicalQuic | 1 | 1 | 2 | 14 | 0 | 0 |
| 1% | NaivePqcQuic | 4 | 4 | 5 | 54 | 0 | 3000 |
| 1% | DraftMtcQuic | 3 | 3 | 4 | 40 | 0 | 2000 |
| 1% | ChronosMtc | 1 | 1 | 1 | 6 | 8 | 0 |
| 3% | ClassicalQuic | 1 | 1 | 2 | 56 | 0 | 0 |
| 3% | NaivePqcQuic | 4 | 5 | 6 | 131 | 0 | 3000 |
| 3% | DraftMtcQuic | 3 | 4 | 5 | 119 | 0 | 2000 |
| 3% | ChronosMtc | 1 | 1 | 1 | 8 | 70 | 0 |
| 5% | ClassicalQuic | 1 | 1 | 3 | 83 | 0 | 0 |
| 5% | NaivePqcQuic | 4 | 6 | 7 | 271 | 0 | 3000 |
| 5% | DraftMtcQuic | 3 | 4 | 6 | 211 | 0 | 2000 |
| 5% | ChronosMtc | 1 | 1 | 1 | 5 | 151 | 0 |
| 10% | ClassicalQuic | 1 | 2 | 4 | 187 | 0 | 0 |
| 10% | NaivePqcQuic | 4 | 6 | 8 | 547 | 0 | 3000 |
| 10% | DraftMtcQuic | 3 | 5 | 7 | 471 | 0 | 2000 |
| 10% | ChronosMtc | 1 | 1 | 2 | 17 | 223 | 0 |

## Glass's delta of ChronosMtc against each control

| Loss | Control | delta (p99 rounds) | Relative p99 change | Effect size | Rank status |
|---|---|---|---|---|---|
| 1% | ClassicalQuic | -0.025 | -0.3% | small | consistent loss |
| 1% | NaivePqcQuic | -10.794 | -75.1% | large | consistent win |
| 1% | DraftMtcQuic | -7.724 | -66.9% | large | consistent win |
| 3% | ClassicalQuic | -0.123 | -4.3% | small | consistent loss |
| 3% | NaivePqcQuic | -6.114 | -75.8% | large | consistent win |
| 3% | DraftMtcQuic | -4.605 | -67.7% | large | consistent win |
| 5% | ClassicalQuic | -0.178 | -7.4% | small | consistent loss |
| 5% | NaivePqcQuic | -4.952 | -76.4% | large | consistent win |
| 5% | DraftMtcQuic | -3.899 | -68.4% | large | consistent win |
| 10% | ClassicalQuic | -0.268 | -14.0% | small | consistent loss |
| 10% | NaivePqcQuic | -4.048 | -77.6% | large | consistent win |
| 10% | DraftMtcQuic | -2.812 | -70.4% | large | consistent win |

## Five-layer cost model (ChronosMtc)

| Layer | mean ns | p99 ns | share |
|---|---|---|---|
| L1_InitAndKeyShare | 37700 | 37700 | 17.7% |
| L2_ServerFlightAndFec | 68000 | 68800 | 31.8% |
| L3_NetworkTransportAndRtt | 41875 | 0 | 19.6% |
| L4_ClientFecDecodeAndMtcVerify | 62424.4125 | 69600 | 29.2% |
| L5_EbpfGuardAndAlert | 3544.805 | 3520 | 1.7% |

## Calibration (real cryptography, executed)

| Check | Result |
|---|---|
| Hybrid key agreement | true |
| ML-DSA-65 over external mu | true |
| Merkle inclusion proof | true |
| Skip-link plan over 1024 landmarks | true (10 hops) |
| FEC reconstruction after 1 loss | true (2421 B block) |
| Guard caught downgrade in PqOnly | true |
| Split-view fork rejected | true |
| ChronosMTC Flight 1 at 3% loss | 2997 B of 3600 B credit |

Calibrated constants: keygen 37000 ns, encaps 22000 ns, DSA verify 42000 ns, RS encode 3200 ns/shard, RTT 1000000 ns, PTO 3000000 ns.

Effects in Figure 2 whose paired interval excludes zero and whose mean is at least 10 SMS (unadjusted for multiplicity; all 90 cells are in fig2_ablation_matrix.csv).

| Attacker | Layer removed | Leaked SMS: paired difference [95 % interval] | Legitimate completion (pp) [95 % interval] |
|---|---|---:|---:|
| spoofed platform header | L9 adaptive caps | +310 [+194, +421] | +28.69 [+21.13, +35.30] |
| residential, farmed CAPTCHA | L9 adaptive caps | +310 [+194, +421] | +28.69 [+21.13, +35.30] |
| residential, aged fingerprints | L9 adaptive caps | +310 [+194, +421] | +28.69 [+21.13, +35.30] |
| spoofed platform header | L0 attestation | -223 [-250, -199] | +31.60 [+23.12, +38.62] |
| sequential numbers | L7 risk | +166 [+154, +176] | -30.81 [-35.75, -25.06] |
| sequential numbers | FB loop | +152 [+144, +158] | -21.99 [-30.77, -12.03] |
| residential, reused profile | FB loop | +138 [+122, +154] | -26.64 [-32.50, -19.49] |
| sequential numbers | FB block key | +121 [+101, +141] | -7.73 [-11.95, -3.71] |
| datacenter rotation | L7 risk | +80 [+69, +91] | -3.80 [-6.15, -1.51] |
| premium-prefix pumping | L5 numbers | +73 [+56, +90] | -2.39 [-3.23, -1.50] |
| residential, reused profile | L1 session | +40 [+30, +48] | -7.19 [-10.38, -4.07] |
| single client | L1 session | +29 [+17, +41] | +0.00 [+0.00, +0.00] |
| residential, reused profile | L9 adaptive caps | +27 [+15, +39] | +4.55 [+2.65, +6.40] |
| sequential numbers | L5 numbers | +12 [+10, +14] | -0.85 [-1.45, -0.33] |

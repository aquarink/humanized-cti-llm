# Equations and Method Notes

## Incident Aggregation

Let a raw telemetry record be denoted as:

```latex
f_i = \{s_i, d_i, p_i, v_i, t_i, x_i\}
```

where \(s_i\) is the source IP, \(d_i\) is the destination IP, \(p_i\) is the protocol, \(v_i\) is the service or destination port, \(t_i\) is the timestamp, and \(x_i\) is the feature vector.

An incident \(I_k\) is constructed by grouping related flows within a temporal window \(\Delta t\):

```latex
I_k = \{ f_i \mid t_i \in [T_k, T_k + \Delta t],\; g(f_i) = k \}
```

where \(g(f_i)\) is a grouping function based on tactic, technique, protocol, service, destination port, and traffic context.

## Flow Rate

```latex
FR(I_k) = \frac{|I_k|}{\max(1,\; t_{\max}(I_k) - t_{\min}(I_k))}
```

where \(|I_k|\) is the number of flows in incident \(I_k\).

## Byte Asymmetry Ratio

```latex
BAR(I_k) =
\frac{
\max(B_{orig}(I_k), B_{resp}(I_k))
}{
\max(1,\; \min(B_{orig}(I_k), B_{resp}(I_k)))
}
```

where \(B_{orig}\) and \(B_{resp}\) are aggregated originator and responder byte volumes.

## Threat Mapping Function

```latex
M(I_k) \rightarrow \{ tactic, technique, confidence, rationale \}
```

The mapping function \(M\) aligns incident-level abstraction with MITRE ATT&CK. For UWF-ZeekData24, mapping uses dataset-provided ATT&CK labels. For DDoS datasets, repeated attack-labeled high-volume traffic is mapped to Impact / T1498.

## Mapping Coverage

```latex
Coverage = \frac{|\{ I_k \mid technique(I_k) \neq none \}|}{|I|}
```

## Narrative Quality Score

For human or LLM-as-a-judge evaluation:

```latex
NQS(I_k) =
\frac{
w_c C_k + w_a A_k + w_l L_k - w_u U_k
}{
w_c + w_a + w_l + w_u
}
```

where \(C_k\) is clarity, \(A_k\) is actionability, \(L_k\) is analyst alignment, and \(U_k\) is unsupported claim score. Higher \(U_k\) penalizes unsupported narrative claims.

## Evidence Traceability Score

```latex
ETS(I_k) = \frac{|Claims_{supported}(I_k)|}{|Claims_{total}(I_k)|}
```

This score measures whether narrative claims can be traced back to incident abstraction fields.

## Quantitative Metrics for Intermediate Components

```latex
Precision = \frac{TP}{TP + FP}
```

```latex
Recall = \frac{TP}{TP + FN}
```

```latex
F1 = 2 \times \frac{Precision \times Recall}{Precision + Recall}
```

```latex
Accuracy = \frac{TP + TN}{TP + TN + FP + FN}
```

These metrics evaluate intermediate filtering or mapping components, not the final CTI narrative quality.


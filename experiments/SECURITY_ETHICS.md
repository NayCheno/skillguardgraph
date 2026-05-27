# Security and Ethics

This prototype is for defensive research only.

## Allowed use

- Analyze skill metadata for excessive permissions.
- Normalize safe runtime traces.
- Evaluate policy constraints on synthetic data.
- Build reproducible benchmarks with benign-paired cases.

## Disallowed use

- Generate operational payloads against real systems.
- Exfiltrate real data or credentials.
- Run dynamic probing against third-party services without authorization.
- Publish undisclosed vulnerabilities without responsible disclosure.

## Benchmark safety rules

1. Use fake credentials only.
2. Use synthetic enterprise documents only.
3. Route all egress tests to local sinkholes.
4. Keep attack cases non-operational by default.
5. Provide minimized examples and remove real targets.


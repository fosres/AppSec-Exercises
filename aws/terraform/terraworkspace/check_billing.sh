aws ce get-cost-and-usage \
  --time-period Start=2026-04-01,End=2026-04-28 \
  --granularity MONTHLY \
  --metrics "UnblendedCost" \
  --profile lab-sso

# keyrisk plugin

This plugin provides three parts:

1. Front-end self verification UI at `/key-risk`.
2. 24/7 worker crawler that scans configurable realms (default `bsc`) for risky key patterns.
3. External API for risk data consumers.

## Endpoints

- `GET /key-risk` UI for self-verification.
- `POST /key-risk/api/v1/self-verify` run immediate verification for one address.
- `GET /key-risk/api/v1/address/<address>?realm=bsc` get stored finding/profile for an address.
- `GET /key-risk/api/v1/findings?realm=bsc&min_score=0&limit=50` list findings.
- `GET /key-risk/api/v1/realms` list realm scan progress.

## Worker behavior

The worker starts in `postboot.py` and runs continuously.

Default risk flags:

- `old_key`: first seen age is greater than or equal to 30 days.
- `high_transaction_volume`: transaction count estimate is above threshold.

## Config knobs

Set these values in your node config if desired:

- `key_risk_realms`: list of realm definitions. Example:

```json
[
  {
    "name": "bsc",
    "type": "bsc",
    "api_base": "https://api.bscscan.com/api",
    "api_key": "YOUR_BSCSCAN_KEY",
    "start_block": 0
  }
]
```

- `key_risk_poll_interval_seconds` (default `45`)
- `key_risk_http_timeout` (default `10`)
- `key_risk_max_tx_scan` (default `2000`)
- `key_risk_max_blocks_per_cycle` (default `4`)
- `key_risk_max_addresses_per_cycle` (default `250`)
- `key_risk_max_concurrency` (default `8`)
- `key_risk_min_key_age_days` (default `30`)
- `key_risk_high_tx_threshold` (default `200`)

## Collections

- `key_risk_realm_state`
- `key_risk_profiles`
- `key_risk_findings`

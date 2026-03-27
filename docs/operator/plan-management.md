# Plan Management

Subscription plans define what users can purchase and what resources their VMs receive.

## On-Chain vs Off-Chain

Plans have two sides:

- **On-chain**: Plan ID and price (in payment token per day). Created via `bw plan create`. This is what the subscription contract knows.
- **Off-chain**: Resource limits, display name, description. Stored locally in host config. This is what the monitor enforces.

The signup page combines both — it shows the plan name and specs from the local config alongside the price from the contract.

## Creating Plans

Plans are created during wizard finalization (one default plan) and can be added via CLI:

```bash
# Create a plan on-chain (returns plan ID)
bw plan create "Pro VM" 100    # 100 cents/day

# The plan ID is printed to stdout — use it in the local config
```

## Resource Profiles

::: info
Resource profile enforcement requires the blockhost-monitor component (in development). Plans currently define price only.
:::

Local config maps plan IDs to resource envelopes:

```yaml
# /etc/blockhost/plans.yaml (future)
plans:
  1:
    name: "Basic VM"
    cpu_cores: 2
    memory_mb: 4096
    disk_mb: 51200
    bandwidth_mbps: 100
    iops_limit: 1000
    burst:
      cpu_cores: 4
      duration_sec: 300
  2:
    name: "Pro VM"
    cpu_cores: 4
    memory_mb: 8192
    disk_mb: 102400
    bandwidth_mbps: 500
    iops_limit: 5000
```

## Admin Panel Integration

Plan management through the admin panel is planned — create, edit, and deactivate plans from the web interface instead of CLI. The on-chain plan creation will still happen via transaction, but the admin panel will handle the local resource profile configuration.

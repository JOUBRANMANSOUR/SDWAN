# Preserved v4 baseline

`../sdwan_v4` is a read-only Phase-1 reference for this successor. It is not imported as a writable runtime state store and it will not be replaced by v5.

The full file manifest is [`preservation/sdwan_v4.sha256`](preservation/sdwan_v4.sha256). Verify it with:

```bash
cd /home/joubran/projects/sdwan-lab
sha256sum -c sdwan_v5/preservation/sdwan_v4.sha256
```

Phase-1 is preserved because it supplies useful patterns: validated three-transport configuration, C NFQUEUE+nDPI pre-encryption metadata, CONNMARK flow pinning, explicit route-slot tables 101/102/103, Ryu OpenFlow underlay control, and local blackout/remap primitives. v5 replaces its all-router registration, shared-token device identity, ephemeral local identity, scalar hub assignment, volatile desired state, and old-hub-first failover transaction.

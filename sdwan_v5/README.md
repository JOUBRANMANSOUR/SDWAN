# SD-WAN v5 research laboratory

v5 is a separate successor to the preserved v4 reference. It implements the control-plane and local-state architecture for dual-attached spokes, durable ownership and desired state, secure ZTP, and bounded Data Center/SaaS/cloud experiments. It is a research lab, not a production-ready deployment.

The canonical working root is `/mnt/data/sdwan-lab`. The original `/home/joubran/projects/sdwan-lab/sdwan_v4` remains untouched; `/mnt/data/sdwan-lab/sdwan_v4` is its verified preservation copy. Run:

```bash
cd /mnt/data/sdwan-lab
bash sdwan_v5/scripts/validate_static.sh
```

Read [ARCHITECTURE.md](ARCHITECTURE.md), [ZTP_SECURITY_MODEL.md](ZTP_SECURITY_MODEL.md), [DATABASE_SCHEMA.md](DATABASE_SCHEMA.md), and [UBUNTU_RUNBOOK.md](UBUNTU_RUNBOOK.md) before privileged execution.

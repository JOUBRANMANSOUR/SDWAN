UPDATE devices SET assigned_site='site' || substr(assigned_site,5) WHERE assigned_site GLOB 'node[0-9]*';
UPDATE claims SET assigned_site='site' || substr(assigned_site,5) WHERE assigned_site GLOB 'node[0-9]*';
UPDATE certificates SET assigned_site='site' || substr(assigned_site,5) WHERE assigned_site GLOB 'node[0-9]*';
UPDATE ztp_audit_events SET target='site' || substr(target,5) WHERE target GLOB 'node[0-9]*';

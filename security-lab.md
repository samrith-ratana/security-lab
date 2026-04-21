# Security Lab Professional Command Guide

This guide is for **authorized lab use only** in your local `security-lab` environment.
Use these commands only with written permission and defined scope.

## 1. Mission and Professional Mindset

A professional cyber team should always:
- Define scope before touching systems.
- Log every action with timestamp.
- Validate findings with evidence.
- Minimize impact to systems.
- Report risk, business impact, and fix priority.

## 2. Lab Scope (From `docker-compose.yml`)

Targets in this lab:
- Reverse proxy: `reverse-proxy`
- Web targets: `dvwa`, `webgoat`, `juiceshop`, `api-lab`
- Internal targets: `metasploitable`, `dvwa-db`
- Defense stack: `suricata`, `elasticsearch`, `kibana`, `packet-sniffer`

## 3. Start and Validate the Environment

### Bring up all services
```bash
docker compose up -d
```

### Check service health/status
```bash
docker compose ps
docker compose logs --tail=50 reverse-proxy dvwa webgoat juiceshop suricata kibana
```

### Verify attack surfaces from host
```bash
curl -I http://localhost/dvwa/
curl -I http://localhost/webgoat/
curl -I http://localhost/juice/
curl -I http://localhost/api/get
```

When to perform:
- At start of each assessment window.
- After config changes.
- Before reporting "service down" issues.

## 4. Baseline Recon (Professional First Action)

### Enter Kali container
```bash
docker exec -it kali bash
```

### Install standard tools once in Kali
```bash
apt update && apt install -y nmap nikto sqlmap gobuster curl jq
```

### Discover hosts and common ports inside DMZ
```bash
nmap -sn 172.18.0.0/16
nmap -sV -sC dvwa webgoat juiceshop api-lab metasploitable
```

### Web endpoint mapping
```bash
gobuster dir -u http://reverse-proxy/dvwa/ -w /usr/share/wordlists/dirb/common.txt
gobuster dir -u http://reverse-proxy/juice/ -w /usr/share/wordlists/dirb/common.txt
```

When to perform:
- Before vulnerability scanning or exploit simulation.
- After new services are added.

Professional advantage:
- Reduces false positives by understanding live services first.

## 5. Web App Testing (Controlled and Reproducible)

### DVWA quick assessment
```bash
nikto -h http://reverse-proxy/dvwa/
```

### API behavior and input handling checks
```bash
curl -s http://reverse-proxy/api/get | jq
curl -X POST http://reverse-proxy/api/post -d 'test=1'
```

### SQLi validation (only in this lab target)
```bash
sqlmap -u "http://reverse-proxy/dvwa/vulnerabilities/sqli/?id=1&Submit=Submit" --batch --risk=1 --level=1
```

When to perform:
- After recon and before any deep exploit attempts.

Professional advantage:
- Produces reproducible command evidence for reports.

## 6. Network and Lateral-Movement Simulation (Authorized Lab)

### Enumerate SMB/legacy services on metasploitable
```bash
nmap -sV -p 21,22,23,25,80,139,445,3306 metasploitable
```

### Safe packet-level visibility from sniffer container
```bash
docker logs -f packet-sniffer
```

### Optional traffic generation for detection tuning
```bash
docker exec -it kali bash -lc "for i in {1..20}; do curl -s http://reverse-proxy/api/get > /dev/null; done"
```

When to perform:
- Purple-team exercises.
- Detection engineering tuning.

Professional advantage:
- Lets Blue Team verify alert quality against known benign and suspicious traffic.

## 7. Blue Team Monitoring and Alerting

### Suricata live logs
```bash
docker logs -f suricata
```

### Elasticsearch health checks
```bash
curl -s http://localhost:9200/_cluster/health?pretty
curl -s http://localhost:9200/_cat/indices?v
```

### Kibana access
```bash
# Open in browser
http://localhost:5601
```

When to perform:
- During and after Red Team activity.
- After rule changes and stack restarts.

Professional advantage:
- Confirms telemetry pipeline is complete (sensor -> index -> dashboard).

## 8. Incident Response Workflow Commands

### 1) Detect
```bash
docker compose logs --since=10m suricata packet-sniffer
```

### 2) Triage
```bash
docker exec -it packet-sniffer sh -lc "ip a && netstat -tunap"
docker exec -it reverse-proxy sh -lc "nginx -T | head -n 80"
```

### 3) Contain (example: isolate compromised service)
```bash
docker compose stop dvwa
```

### 4) Eradicate/Recover (clean restart)
```bash
docker compose rm -sf dvwa
docker compose up -d dvwa
```

### 5) Validate
```bash
curl -I http://localhost/dvwa/
docker compose logs --tail=100 dvwa reverse-proxy
```

Professional advantage:
- Structured IR phases reduce panic and preserve evidence quality.

## 9. Evidence Collection and Reporting Commands

### Create a timestamped report directory
```bash
mkdir -p reports/$(date +%F_%H%M)
```

### Save command outputs as evidence
```bash
nmap -sV dvwa webgoat juiceshop api-lab metasploitable -oN reports/$(date +%F_%H%M)/nmap.txt
docker compose ps > reports/$(date +%F_%H%M)/services.txt
docker compose logs --no-color suricata > reports/$(date +%F_%H%M)/suricata.log
```

### Capture packet evidence (from sniffer container)
```bash
docker exec -it packet-sniffer sh -lc "tcpdump -i eth0 -w /tmp/lab_capture.pcap -c 500"
docker cp packet-sniffer:/tmp/lab_capture.pcap reports/$(date +%F_%H%M)/lab_capture.pcap
```

When to perform:
- During each major test scenario.
- Immediately after notable detection or incident.

## 10. Advanced Professional Practices

### A. Run with strict scope control
- Keep a written list of allowed targets:
  - `reverse-proxy`, `dvwa`, `webgoat`, `juiceshop`, `api-lab`, `metasploitable`
- Avoid scanning outside Docker lab ranges.

### B. Use low-noise first, high-impact last
1. Passive checks and service discovery.
2. Safe validation tests.
3. Controlled exploit simulation.
4. Recovery validation.

### C. Always pair attack with detection
- Every Red Team action should produce a Blue Team query or alert validation.
- Example flow:
  1. Run `nmap` scan.
  2. Confirm Suricata logs.
  3. Document detection coverage gap.

### D. Measure maturity with metrics
Track per exercise:
- Time to Detect (TTD)
- Time to Triage (TTT)
- Time to Contain (TTC)
- False positive ratio
- Detection coverage by attack technique

## 11. Fast Command Bundle (Daily Professional Routine)

```bash
# 1) Start and verify

docker compose up -d
docker compose ps

# 2) Recon snapshot

docker exec -it kali bash -lc "nmap -sV dvwa webgoat juiceshop api-lab metasploitable"

# 3) Blue visibility

docker logs --tail=100 suricata
curl -s http://localhost:9200/_cluster/health?pretty

# 4) Evidence export

mkdir -p reports/$(date +%F_%H%M)
docker compose logs --no-color > reports/$(date +%F_%H%M)/full-lab.log
```

## 12. Professional Output Template (Use in your report)

- Objective: What was tested and why.
- Scope: Exact systems and timeframe.
- Method: Commands/tools used.
- Findings: Severity, evidence, impact.
- Detection Result: Detected/not detected, alert source.
- Recommendation: Fix + priority + owner.
- Retest Plan: How to verify remediation.

---

If you want, the next step is I can create `commands.txt` with these commands grouped by `red-team`, `blue-team`, and `incident-response` for faster execution.
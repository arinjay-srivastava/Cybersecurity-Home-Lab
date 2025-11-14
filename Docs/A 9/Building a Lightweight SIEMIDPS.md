
## Introduction

The purpose of this lab is to build a lightweight Security Information and Event Management (SIEM) and Intrusion Detection and Prevention System (IDPS) pipeline using **Suricata**, **Loki**, **Promtail**, and **LogCLI**. By the end of this exercise, I will be able to explain the core components of a modern SIEM/IDPS, install and configure the necessary tools, and query and correlate security alerts.

| **Tool**     | **Role**                                                                                    |
| ------------ | ------------------------------------------------------------------------------------------- |
| **Suricata** | IDPS engine that inspects packets and generates JSON alerts.                                |
| **Loki**     | Lightweight log aggregation system/SIEM backend that stores logs with labels.               |
| **Promtail** | Log shipper agent that tails log files (like Suricata's `eve.json`) and sends them to Loki. |
| **LogCLI**   | Command-line client for querying logs stored in Loki                                        |

---

## Part 1 - Prepare System

I first installed the necessary utilities (`curl`, `jq`, `unzip`) and Docker, then configured Docker permissions and started the service.

Commands Run
```bash 
# Install curl, jq, and unzip
sudo apt update && sudo apt upgrade -y 
sudo apt -y install curl jq unzip 

# Install Docker
curl -fsSL https://get.docker.com | sudo sh 

# Add my user to the docker group and start a new shell
sudo usermod -aG docker "$USER" 
newgrp docker

# Enable and start the docker service
sudo systemctl enable --now docker
docker --version 
```

![[image_2025-11-08_12-49-17.png]]
![[image_2025-11-08_12-49-37.png]]
![[image_2025-11-08_12-51-24.png]]
![[image_2025-11-08_12-53-16.png]]
![[image_2025-11-08_12-55-48.png]]

---

## Part 2 - Suricata

Suricata is my high-performance Network IDS, IPS, and Network Security Monitoring engine for this lab. I configured it to generate realistic network-security events.

### Preflight Setup for Suricata

I set up the default rule set, created a custom rules file, and configured the main `suricata.yaml` file.

**Commands Run**
```bash
# Download the community rule set
sudo apt -y install suricata-update
sudo suricata-update 
```

![[image_2025-11-08_12-56-54-2.png]]
![[image_2025-11-08_13-04-47.png]]

``` bash
# Find my network interface name (to find my interface name, e.g., ens160)
ip -br a | awk '$1!="lo" {print $1, $3}'
```

![[image_2025-11-08_13-05-35.png]]

```
# Create a directory and file for my custom rules
sudo mkdir -p /etc/suricata/rules
sudo touch /etc/suricata/rules/local.rules 
```

![[image_2025-11-08_13-07-58.png]]

```bash

# Edit /etc/suricata/suricata.yaml (I'll use nano)
sudo nano /etc/suricata/suricata.yaml 

# (Inside nano: I updated default-rule-path and rule-files 
# default-rule-path: /var/lib/suricata/rules
# rule-files:
#   - suricata.rules
#   - /etc/suricata/rules/local.rules
# Then I searched the following commadn
af-packet
# (Inside nano: I updated the af-packet interface with my interface name, e.g., ens33
# af-packet:
#   interface: ens33
```
![[image_2025-11-08_13-28-04.png]]
![[image_2025-11-08_13-27-46.png]]

```bash
# Test and validate Suricata configuration
sudo suricata -T -c /etc/suricata/suricata.yaml -v 
```

![[image_2025-11-08_13-31-41.png]]

I used the `man suricata` command to get details and understand what the flags are about
- **`-T`**: Runs a **test** mode. Suricata will parse and validate the configuration and rules without actually running as an IDS/IPS engine.
- **`-c /etc/suricata/suricata.yaml`**: Specifies the **configuration file** to be used. It tells Suricata exactly which YAML file to load for its settings.
- **`-v`**: Enables **verbose** output, providing more detailed information about the configuration loading and rule testing process

---

### Install and Run Suricata

I installed and started Suricata manually so I could control it and ensure it writes logs.

**Commands Run**
```bash
# Install Suricata
sudo apt -y install suricata 
sudo systemctl stop suricata 
```
![[image_2025-11-08_13-39-38.png]]

```bash
# Confirm it writes logs (hit Control + C to exit after confirming output)
sudo tail -f /var/log/suricata/eve.json | jq 
```
![[image_2025-11-08_13-55-12.png]]

![[College Work/Fall 25/NS (Network Security)/Assignment 9/image.png]]

I examined the `eve.json`. While I haven't triggered a new alert yet, based on the general traffic Suricata monitors, the common event types ("event_type") I see in the log are:

- **`flow`**: Records information about the start and end of a network flow (connection).
- **`dns`**: Records DNS query and response activity.
- **`http`**: Records HTTP request and response metadata.
- **`stats`**: Records periodic statistics about Suricata's performance.

Later in the lab, I expect to see the **`alert`** event type when an intrusion signature is matched.

---

## Part 3 - Loki

Loki acts as the central log database, receiving logs from Promtail and enabling fast searching using labels.

### Preflight Setup for Loki

I created the necessary configuration and data directories and set permissions for Loki.

**Commands Run**
```bash
# Create directories for Loki
sudo mkdir -p /etc/loki /var/lib/loki/{chunks,rules}

# Create a default Loki configuration file (using a heredoc)
cat <<'EOF' | sudo tee /etc/loki/loki-config.yml
auth_enabled: false
server:
  http_listen_port: 3100
common:
  path_prefix: /var/lib/loki
storage:
  filesystem:
    chunks_directory: /var/lib/loki/chunks
    rules_directory: /var/lib/loki/rules
replication_factor: 1
ring:
  kvstore:
    store: inmemory
schema_config:
  configs:
  - from: 2020-10-24
    store: boltdb-shipper
    object_store: filesystem
    schema: v13
    index:
      prefix: index_
      period: 24h
EOF 
```
![[image_2025-11-08_14-13-54.png]]
![[image_2025-11-08_14-14-25.png]]
```bash
# Fix permissions
sudo chown -R 10001:10001 /var/lib/loki
sudo chmod -R u+rwX /var/lib/loki
```
![[image_2025-11-08_14-20-01.png]]
### Run Loki

I ran Loki as a Docker container, mapping its configuration and data directories.

**Commands Run**
```bash
# Start Loki in a Docker container
sudo docker run -d --name loki -p 3100:3100 \
  -v /etc/loki:/etc/loki \
  -v /var/lib/loki:/var/lib/loki \
  grafana/loki:2.9.8 -config.file=/etc/loki/loki-config.yml
```
![[image_2025-11-08_14-20-14.png]]

To break this down:

- -d: runs in detached (background) mode.
- --name loki: names the container “loki” for easy reference.
- -p 3100:3100: maps port 3100 from the container to your VM, so you can reach Loki at http://localhost:3100 .
- -v /etc/loki:/etc/loki: mounts your host’s config directory into the container.
- -v /var/lib/loki:/var/lib/loki: mounts the data directory so logs persist even if the container restarts. 
- grafana/loki:2.9.8: specifies the Loki image and version.

```bash
# Check that Loki is running and ready
sudo docker ps 
curl -s http://localhost:3100/ready; echo
```
![[image_2025-11-08_14-24-07.png]]

- **Loki's exposed port**: Loki exposes port **3100** (defined by `server.http_listen_port: 3100` in the config and mapped by `-p 3100:3100` in the `docker run` command).
- **API path for log data**: The log data is received via the push API path, which is **`/loki/api/v1/push`** (as seen in the Promtail configuration later on).

---

## Part 4 - Run Promtail (Log Shipper)

Promtail is the agent that tails Suricata's `eve.json` log file, attaches the helpful label `job="suricata"`, and sends the log lines to Loki

### Promtail Setup and Run

I created the necessary folders, wrote the Promtail configuration file, and ran it in Docker.

**Commands Run**
```bash
# Create Promtail folders
sudo mkdir -p /etc/promtail /var/lib/promtail
# Write the Promtail config file
cat <<'EOF' | sudo tee /etc/promtail/promtail-config.yml
server:
  http_listen_port: 9080
  grpc_listen_port: 0
clients:
  - url: http://localhost:3100/loki/api/v1/push 
positions:
  filename: /var/lib/promtail/positions.yaml 
scrape_configs:
  - job_name: suricata 
    static_configs: 
    - targets: [localhost] 
      labels:
        job: suricata
        __path__: /var/log/suricata/eve.json 
EOF
```
![[image_2025-11-08_14-25-16.png]]
![[image_2025-11-08_14-26-19.png]]

```bash
# Run the Promtail container
sudo docker run -d --name promtail -p 9080:9080 \
  -v /etc/promtail:/etc/promtail \
  -v /var/log/suricata:/var/log/suricata:ro \
  -v /var/lib/promtail:/var/lib/promtail \
  grafana/promtail:2.9.8 \
  -config.file=/etc/promtail/promtail-config.yml 
```
![[image_2025-11-08_14-27-04.png]]

To break this down:
- -d: run in background (detached).
- --name promtail: easy to reference later ( docker logs promtail ).
- -p 9080:9080: maps container’s port 9080 to the VM’s 9080 (Promtail’s HTTP status page).
- -v /etc/promtail:/etc/promtail: mount your config into the container.
- -v /var/log/suricata:/var/log/suricata:ro: mount Suricata logs read-only (:ro) so Promtail can read eve.json .
- -v /var/lib/promtail:/var/lib/promtail: mount the positions storage so progress persists across restarts. 
- grafana/promtail:2.9.8: the Promtail image and version.
- -config.file=...: tell Promtail where the config is inside the container (the mounted path).

- **Promtail's Role**: Promtail is the **log shipper/agent**. Its primary job is to **collect** log data from files on the host system (like Suricata's `eve.json`), attach metadata **labels** to each line, and **send/push** that data to Loki.
- **Loki's Role**: Loki is the **central log database/SIEM backend**. Its primary job is to **receive**, **store** logs efficiently (indexing only the labels), and provide a fast way to **search and query** the collected data.

- **Problem Solved**: The position file (`/var/lib/promtail/positions.yaml`) solves the problem of **duplication and missed logs** when Promtail is restarted.
- **How it Works**: It acts as a **bookmark** or checkpoint, keeping track of the **offset** (how many bytes/lines it has read) for each log file it is tailing. If the Promtail container restarts, it reads the position file and resumes reading the log file from the last known good position, ensuring it doesn't resend old log lines or miss new ones written while it was down.


---

## Part 5 – Install LogCLI and Test Queries

LogCLI is the command-line tool I'll use to query Loki.
### Install LogCLI

I downloaded, extracted, and configured the LogCLI binary.

**Commands Run**
```bash
# Download and install LogCLI
curl -L https://github.com/grafana/loki/releases/download/v2.9.8/logcli-linux-amd64.zip -o /tmp/logcli.zip 
sudo unzip -o /tmp/logcli.zip -d /usr/local/bin
sudo mv /usr/local/bin/logcli-linux-amd64 /usr/local/bin/logcli 
sudo chmod +x /usr/local/bin/logcli 
logcli --version 
```
![[image_2025-11-08_14-41-48.png]]
```bash
# Verify connectivity and list available labels
logcli labels --addr=http://localhost:3100
# Query recent logs
logcli query --addr=http://localhost:3100 --limit=10 '{job="suricata"}'
```
![[image_2025-11-08_14-42-25.png]]

Based on my configuration, the labels I expect to see attached to my Suricata logs are:

- **`job`**: `suricata`
- **`path`**: `/var/log/suricata/eve.json` 

- **Labels (Loki)**: Labels are **metadata key/value pairs** used to create an **index stream**. Loki only indexes these labels (e.g., `job="suricata"`, `host="serverA"`). They are used for **filtering and grouping log streams** _before_ searching the actual log content. This approach is lightweight and fast for initial filtering.
- **Full-Text Indexes (e.g., Elasticsearch)**: Full-text indexes create an inverted index for **every word** (or token) in every log line. This allows for extremely fast searches on _any_ content within the logs, but it is **resource-heavy** in terms of storage and processing power compared to indexing only labels.

---

## Part 6 – Generate Alerts and Analyze

Now I will trigger a test alert to verify the entire SIEM pipeline is working.
### Add Custom Rule and Trigger Alert

I'm adding a custom Suricata rule to detect a specific HTTP User-Agent string.

**Commands Run**
```bash
# Add a custom Suricata rule to local.rules
echo 'alert http any any -> any any (msg:"LAB UA hit"; http.user_agent; content:"CPS-NETSEC-LAB"; sid:9900001; rev:1;)' \
| sudo tee -a /etc/suricata/rules/local.rules 
# Restart Suricata to load the new rule
sudo systemctl restart suricata 
sudo suricata -T -c /etc/suricata/suricata.yaml -v 

# Trigger the alert
curl -A "CPS-NETSEC-LAB" http://example.com/ || true 
```
![[image_2025-11-08_14-48-45.png]]
```bash
# Query alerts in Loki
logcli query --addr=http://localhost:3100 --limit=50 \
  '{job="suricata"} |= "event_type\":\"alert\"" | json | line_format "
 {{.alert.signature}}"' 
```
![[image_2025-11-08_14-50-10.png]]

The command `logcli query --addr=http://localhost:3100 --limit=50 '{job="suricata"} |= "event_type\":\"alert\"" | json | line_format "{{.alert.signature}}"'` is performing the following steps:

1. **`logcli query --addr=...`**: Connects to the Loki server running at `http://localhost:3100` to execute a LogQL query.
2. **`--limit=50`**: Instructs Loki to return a maximum of 50 log lines that match the query.
3. **`'{job="suricata"}'`**: This is the **Log Stream Selector**. It filters the massive volume of logs down to a single stream tagged with the label `job=suricata` (i.e., logs that originated from the Suricata agent via Promtail).
4. **`|= "event_type\":\"alert\""`**: This is the **Line Filter**. After selecting the stream, it searches the content of the log lines for the literal string `event_type:"alert"`, effectively showing only the security alerts generated by Suricata.
5. **`| json`**: This is a **LogQL Parser**. It parses the log line (which is a JSON object) so that fields within the log can be accessed.
6. **`| line_format "{{.alert.signature}}"`**: This is a **LogQL Formatter**. It uses a Go template to reformat the output, extracting only the value of the `alert.signature` field (e.g., "LAB UA hit") and displaying _only_ that value, making the results clean and focused.

---

## Part 7 – Correlation Challenge

I will run the correlation command to find the top source IPs generating alerts.

**Commands Run**
```bash
logcli query --addr=http://localhost:3100 --limit=1000 --since=5m \
  '\{job="suricata"\} |= "event_type\":\"alert\"" | json | line_format "\{\{.src_ip\}\}"' \
  | sort | uniq -c | sort -nr | head
```
![[image_2025-11-08_15-00-18.png]]

This command illustrates that a SIEM (or log tool like Loki/LogCLI) can not only search for specific events but also **aggregate** and **correlate** data to find patterns:

- **Aggregation**: It first extracts the `src_ip` field from thousands of raw log lines (`| line_format "{{.src_ip}}"`). It then counts the occurrences of each unique IP (`| uniq -c`) and sorts them by frequency (`| sort -nr`). This aggregates raw event data into a meaningful, summarized metric.
- **Correlation**: The command is correlating multiple separate `alert` events by a common field (`src_ip`) over a specific time window (`--since=5m`). This is a fundamental SIEM function, turning a stream of individual events into an indication of a concentrated threat or activity from a single source.


A Security Operations Center (SOC) would use this information in an investigation to:

1. **Prioritize/Triage:** The IP address with the highest alert count (the top result) immediately becomes the highest priority target for investigation. It indicates a source that is actively and persistently attacking or probing the network.
2. **Scope the Incident:** The SOC knows precisely _which_ hosts are the most active threat sources. This helps them quickly define the scope of the incident and focus defensive efforts (e.g., blocking that IP at the firewall).
3. **Contextual Enrichment:** They would take the top IP and run further queries in the SIEM to find out _what kind_ of alerts it was generating, _when_ the activity started, and _what_ was the destination IP/port to fully understand the nature and severity of the attack.

---

## Part 8 – Create and Test Your Own Custom Rule

### Rule Creation and Testing

I will write a custom Suricata rule to detect a specific HTTP header value that is different from the one used in Part 6. This rule will alert whenever a request contains the header **`X-Attacker-Header`** with the value **`NETSEC-TEST`**.

### 1. Write and Add the Custom Rule

I'll use the `echo` and `sudo tee -a` commands to append the new rule directly to my local rules file, `/etc/suricata/rules/local.rules`.

**Commands Run**
```bash 
# 1. Add the custom Suricata rule to local.rules
echo 'alert http any any -> any any (msg:"LAB-Custom-HTTP-HEADER-TEST";
http.header; content:"X-Attacker-Header|3a 20|NETSEC-TEST"; sid:9900003;  
rev:1;)' \ | sudo tee -a /etc/suricata/rules/local.rules

# 2. Restart Suricata to load the new rule
sudo systemctl restart suricata
sudo suricata -T -c /etc/suricata/suricata.yaml -v

 ```
![[image_2025-11-08_16-15-06.png]]

### 2. Trigger the Alert

I will use `curl` with the **`-H`** flag to manually add the specific HTTP header that my rule is designed to detect.

**Commands Run**
```bash
# Trigger the alert by sending an HTTP request with the specific header
curl -H "X-Attacker-Header: NETSEC-TEST" http://example.com/ || true

# Query alerts in Loki to verify your new rule
logcli query --addr=http://localhost:3100 --limit=50 \
  '{job="suricata"} |= "LAB-Custom-HTTP-HEADER-TEST"' | head -n 5
```

![[image_2025-11-08_16-16-16.png]]

### Details about my Rule and some questions

1. What condition did my rule detect?
   My custom rule detected an **HTTP request header** where the header name was `X-Attacker-Header` and its corresponding value was `NETSEC-TEST`.
   
2. How did I  test and confirm that it triggered correctly?|
   tested the rule by running the `curl` command with the **`-H`** flag to send an HTTP request that contained the exact pattern specified in my rule:

  ```bash
curl -H "X-Attacker-Header: NETSEC-TEST" http://example.com/
```

I confirmed it triggered correctly by running a **LogCLI query** that searched Loki for the unique alert message:

```bash
logcli query ... '{job="suricata"} |= "LAB-Custom-HTTP-HEADER-TEST"'
```
The successful return of the log line with my custom message confirmed the entire pipeline (Suricata detection, Promtail shipping, and Loki querying) worked.

3. How did I modify my rule to make it more specific (to reduce false positives)?

To make the rule more specific and reduce false positives, I would add a **directional constraint** and a **protocol constraint**:
- **Direction:** I would change the rule to only trigger if the traffic is going from an **internal source** (my network, e.g., `$HOME_NET`) to an **external destination** (`$EXTERNAL_NET`), instead of `any any -> any any`.
- **Protocol/Port:** I would specify that the traffic must be on a standard HTTP port like **80** or **8080**, rather than allowing it on _any_ port.

**Modified Rule Example:**

```bash 
alert http $HOME_NET any -> $EXTERNAL_NET 80 (msg:"LAB-Custom-HTTP-HEADER-TEST"; http.header; content:"X-Attacker-Header|3a 20|NETSEC-TEST"; sid:9900003; rev:2;)
```

4. Why is fine-tuning rules important in real-world intrusion detection?

Fine-tuning rules is critical because it manages the **Analyst Signal-to-Noise Ratio**. Rules that are too broad generate an overwhelming number of **False Positives** (alerts on normal, benign traffic), leading to **Alert Fatigue** among security analysts. When analysts are fatigued, they risk missing or ignoring a real attack (a **True Positive**). By fine-tuning, security teams ensure they receive only highly relevant alerts, allowing them to focus their limited time and resources on actual threats.


---

## Part 9 – Cleanup

I will stop and remove the Docker containers and clean up Suricata to finish the lab.

**Commands Run**
```bash
# Stop and remove docker containers
sudo docker stop promtail loki 
sudo docker rm promtail loki 
```
![[College Work/Fall 25/NS (Network Security)/Assignment 9/image-1.png]]

```bash
# Purge Suricata and prune Docker system
sudo apt purge -y suricata 
```
![[College Work/Fall 25/NS (Network Security)/Assignment 9/image-2.png]]
``` bash
sudo docker system prune -a -f 
```
![[College Work/Fall 25/NS (Network Security)/Assignment 9/image-3.png]]

---
## Brief Lab Summary

This lab successfully established a **lightweight Security Information and Event Management (SIEM) and Intrusion Detection and Prevention System (IDPS) pipeline** using four core tools: **Suricata**, **Promtail**, **Loki**, and **LogCLI**.

My primary objective was to build a functioning security monitoring stack. I first installed and configured **Suricata** as the IDPS engine to inspect network packets and generate security events in `eve.json`. Next, I deployed **Loki** as the central log aggregation backend, chosen for its efficiency in indexing logs based on metadata **labels** rather than full-text content . The bridge between these two was **Promtail**, the log shipper, which successfully tailed Suricata's log file, attached the necessary `job="suricata"` label, and pushed the data to Loki.

Finally, I used **LogCLI** to query the data stored in Loki, demonstrating essential SIEM functions. I successfully wrote a custom Suricata rule to detect a specific HTTP header and confirmed the alert propagation throughout the entire pipeline. The final steps involved using LogQL and Unix piping (`sort`, `uniq -c`) to perform basic **correlation** and **aggregation**, identifying the top source IPs generating alerts, which is a critical function for triage in a Security Operations Center (SOC) .

---

## References & Sources

|**Tool**|**Official Documentation**|**Additional Reading**|
|---|---|---|
|**Suricata**|[https://suricata.io/documentation/](https://suricata.io/documentation/)|OISF Docs Configuration Guide 7|
|**Grafana Loki**|[https://grafana.com/docs/loki/latest/](https://grafana.com/docs/loki/latest/)|Loki Architecture 8|
|**Promtail**|[https://grafana.com/docs/loki/latest/clients/promtail/](https://grafana.com/docs/loki/latest/clients/promtail/)|Promtail Configuration Reference 9|
|**LogCLI**|[https://grafana.com/docs/loki/latest/tools/logcli/](https://grafana.com/docs/loki/latest/tools/logcli/)|Query Examples 10|
|**cURL**|[https://curl.se/docs/manpage.html](https://curl.se/docs/manpage.html)|Used to trigger HTTP traffic for Suricata 11|
|**Docker**|[https://docs.docker.com/](https://docs.docker.com/)|Container runtime for Loki/Promtail 12|

---

This exploration is about enabling and configuring UFW (Uncomplicated Firewall) on my Ubuntu Virtual Machine. While implementing took screenshots of the outputs, and wrote short inferences.  

## Part I: Enable UFW

### 1. Check UFW status

`Command: sudo ufw status`

![[image_2025-10-02_12-52-36-1.png]]

- **Output:** The status is shown as `inactive`.
- **Inference:** The firewall is not enabled, so no firewall rules are currently enforced.

### 2) Allow SSH before enabling

`Command: sudo ufw allow 22/tcp`

![[image_2025-10-02_12-52-48.png]]

- **Output:** Terminal shows that rule for port 22/tcp was updated.
- **Inference:** SSH access is ensured before enabling UFW, preventing accidental lockout when accessing remotely.
	Also, its important to allow traffic to flow through port 22 when remotely accessing a server because port 22 is for secure shell traffic, the data flow will be secure.


### 3) Check open ports

`Command: sudo ss -tuln`
  
![[image_2025-10-02_12-56-03.png]]

Here we also enable port 80 and 443 for HTTP and HTTPS respectively.

![[image_2025-10-02_13-06-59-1.png]]

- **Output:** List of listening services with ports like 22 (SSH), 80 (HTTP), and 443 (HTTPS).
- **Inference:** Identifies which services are active; confirms we must allow HTTP (80) and HTTPS (443) for a web server.


### 4) Enable UFW

`Command: sudo ufw enable`
  
![[image_2025-10-02_13-04-31.png]]

- **Output:** Message confirming “Firewall is active and enabled on system startup.”
- **Inference:** UFW is now running and will enforce rules across reboots.


### 5) Check status again

`Command: sudo ufw status` 

![[College Work/Fall 25/NS (Network Security)/image.png]]

- **Output:** Shows UFW is active, with allowed rules (like 22/tcp).
- **Inference:** Confirms that UFW is enabled and applying the specified rules.

  
### 6) Allow web server ports

`Command: sudo ufw allow 80/tcp`
`sudo ufw allow 443/tcp`

![[College Work/Fall 25/NS (Network Security)/image-1.png]]

  - **Output:** Shows the rules are already added and skipped adding existing rules. 
  - **Inference:** The firewall already permits HTTP and HTTPS traffic, allowing web services to function.

### 7) Check verbose status

`Command: sudo ufw status verbose`

![[image_2025-10-02_13-07-25-1.png]]

- **Output:** Shows UFW is active, logging is enabled, and lists allowed/denied rules in detail.
- **Inference:** Verbose mode provides more details, such as default policies (deny incoming, allow outgoing), as well as info about UFW logging status.
  
### 8) Block a specific IP

`Command: sudo ufw deny from 10.0.0.0`

![[image_2025-10-02_13-09-17.png]]
  
- **Output:** Confirmation message “Rule added” for denying traffic from 10.0.0.0.
- **Inference:** UFW will now block all connections originating from that IP address (example: blocking a malicious actor).

### 9) Allow a specific IP on port 587

`Command: sudo ufw allow from 192.168.1.50 to any port 587`
  ![[image_2025-10-02_13-11-00.png]]

- **Output:** Confirmation message “Rule added” for allowing 192.168.1.50 to port 587.
- **Inference:** Grants SMTP mail submission access to the specified IP, since port 587 is commonly used for sending email securely.


### 10) Check rules again

`Command: sudo ufw status verbose`
  
![[image_2025-10-02_13-11-42.png]]

- **Output:** Displays all current rules including SSH, HTTP, HTTPS, blocked IP, and specific IP allowed on port 587.
- **Inference:** Confirms firewall configuration matches intended security rules.
  

## Part II: Enable UFW Logging

### 1) Enable logging

`Command: sudo ufw logging on`
 
![[image_2025-10-02_13-14-47.png]]

- **Output:** Confirmation message “Logging enabled.”
- **Inference:** UFW will now record firewall activity.
  
### 2) Set logging level

`Command: sudo ufw logging high`
  ![[image_2025-10-02_13-15-38.png]]

  - **Output:** Message confirming logging set to `high`.
- **Inference:** UFW will capture detailed information about blocked and allowed traffic.

### 3) View recent logs

`Command: sudo tail -n 10 /var/log/ufw.log`

![[image_2025-10-02_13-18-18.png]]

- **Output:** Shows the latest entries in `/var/log/ufw.log`.
- **Inference:** Provides real-time monitoring of firewall activity and all the updates and enteries can be verified.

### 4) Check for denied traffic

`Command: sudo grep 'DENY' /var/log/ufw.log | tail -n 10

  ![[image_2025-10-02_13-22-01.png]]

- **Output:** No output returned.
- **Inference:** There's no output for denied traffic as we have not denied/blocked any connection just yet.
  
### 5) Check for allowed traffic

`Command:  sudo grep 'ALLOW' /var/log/ufw.log | tail -n 10

![[image_2025-10-02_13-21-40-1.png]]
- **Output:** Shows log entries marked as `[UFW ALLOW]`.
- **Inference:** Confirms that some connections were successfully allowed through the firewall.
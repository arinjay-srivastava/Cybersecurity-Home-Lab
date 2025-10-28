
In this assignment, I’m installing and configuring Snort on my Ubuntu Virtual Machine. This is just a starting point for how I can use Snort, so I’m excited to explore and experiment with the configuration files! 
## Step 1: Update the System

I want to ensure my system is up to date before installing Snort, so I run these commands:

```bash
sudo apt update
sudo apt upgrade -y
```
![[image_2025-10-27_18-32-36.png]]
## Step 2: Install Snort

I’m installing Snort directly using apt with this command:

```bash
sudo apt install snort -y
```

![[image_2025-10-27_18-33-24.png]]

During the installation, I’m prompted to enter the network interface and the HOME_NET IP range that Snort will monitor. I need to decide on:

1. **Network Interface:** I’ll enter the interface I want Snort to monitor (e.g., `eth0`, `enX0`, `ens33`, etc.).
2. **HOME_NET:** I’ll define my home network (e.g., `192.168.1.0/24` for a private network or `any` to monitor all networks).

After installation, I notice Snort is installed to `/etc/snort/` with the default configuration and rules.

To find my network interface, I run this command:

```bash
ip a
```

![[image_2025-10-27_18-33-45-1.png]]


## Step 3: Configure Snort

  ```bash
sudo nano /etc/snort/snort.conf
  ```

![[image_2025-10-27_18-35-17.png]]

## Step 4: Update and Manage Snort Rules

By default, Snort comes with community rules, but I can download and add additional rules for better threat detection.

If I need to, I download community rules with:

```bash
sudo wget https://www.snort.org/downloads/community/community-rules.tar.gz
sudo tar -xvzf community-rules.tar.gz
sudo cp community-rules/* /etc/snort/rules/
```

![[image_2025-10-27_18-41-44.png]]

![[image_2025-10-27_18-43-22.png]]

![[image_2025-10-27_18-53-13.png]]


If I want to add my own rules, I manually edit the local rule file:

```bash
sudo nano /etc/snort/rules/local.rules
```
![[image_2025-10-27_18-53-13.png]]
Then, I add custom rules if needed. For example, I use:

```plaintext
alert icmp any any -> any any (msg:"ICMP detected"; sid:1000001; rev:1;)
```
![[image_2025-10-27_18-53-13.png]]

I check out the various rule files in the `rules` directory. Which rules stick out to me? The `malware.rules` file stood out to me because it contains rules to detect malware-related traffic, which feels critical for security. What is the purpose of rules in general? Rules define patterns in network traffic to identify threats like intrusions or malware, triggering alerts to help me monitor and secure my network.
## Step 5: Test Snort Configuration

After configuring, I test that Snort is working properly by running a configuration test:

```bash
sudo snort -T -c /etc/snort/snort.conf
```
![[image_2025-10-27_18-53-59.png]]
If the configuration is correct, I see a message like:

Snort successfully validated the configuration! (As visible in the screenshot above)

## Step 6: Running Snort in IDS Mode

Now that Snort is installed and configured, I run it in IDS mode to monitor traffic. I specify the interface to monitor (e.g., `eth0`, `enX0`, etc.) with:

```bash
sudo snort -c /etc/snort/snort.conf -i eth0
```
![[image_2025-10-27_18-55-21.png]]

Snort now monitors my network traffic and logs alerts. To exit, I hit `ctrl+c`.

## Step 7: Viewing Snort Logs

Snort logs alerts in the `/var/log/snort/` directory. I go to this directory. I found a file named `snort.alert.fast` in the `/var/log/snort/` directory. It’s empty because I haven’t generated enough network traffic (like ICMP pings) to trigger my rule, or Snort might need more time running as a daemon to log events. It’s likely empty due to insufficient traffic or recent daemon startup.

![[image_2025-10-27_18-59-13.png]]

![[image_2025-10-27_18-59-27.png]]
## Step 8: Running Snort as a Daemon

To run Snort in the background as a daemon, I use the following. I specify the interface to monitor (e.g., `eth0`, `enX0`, etc.):

```bash
sudo snort -D -c /etc/snort/snort.conf -i eth0
```

![[College Work/Fall 25/NS (Network Security)/Assignment 6/image-3.png]]

This keeps Snort running in the background, continuously monitoring my specified network interface.

To see the different processes running in my system, I use the command `top`. If I wait a few seconds, I should see Snort running. 
If I want to stop the Snort process from running, I can use the command 


```bash
    sudo kill -9 [PID]
And from my earlier results I can see that the PID is 2558. Thus the command becomes
    
    sudo kill -9 2558
    ```

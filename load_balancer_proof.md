# How to Prove Your Load Balancer is Active and Working

Here are the **three best ways** to prove to your teacher that your AWS Elastic Beanstalk environment is running behind a Load Balancer.

---

## Proof 1: Check the HTTP Headers (The Easiest Proof)

AWS Application Load Balancers (ALB) append a specific HTTP header to responses: `Server: awselb/2.0`. 

You can test this using the command line (Terminal, PowerShell, or Git Bash):

1. Open your terminal.
2. Run the following command (replace `<your-app-url>` with your actual Elastic Beanstalk URL):
   ```bash
   curl -I http://<your-app-url>
   ```

### What to show your teacher:
Look for the `Server` header in the output. It should look like this:
```http
HTTP/1.1 200 OK
Date: Tue, 19 May 2026 23:20:00 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 1234
Connection: keep-alive
Server: awselb/2.0             <--- PROOF: AWS Application Load Balancer
```

---

## Proof 2: DNS Lookup (The Architectural Proof)

A Single Instance environment points directly to a single IP address. A Load Balanced environment points to the Load Balancer's domain, which resolves to multiple IP addresses.

Run a DNS lookup on your application URL:

1. Open your terminal.
2. Run:
   ```bash
   nslookup <your-app-url>
   ```

### What to show your teacher:
You will see that the alias (CNAME) points to a load balancer endpoint (containing `.elb.amazonaws.com`), and it resolves to **multiple distinct IP addresses** (usually 2 or more, corresponding to different AWS Availability Zones):

```text
Non-authoritative answer:
Name:    cyber-security-env.ap-south-1.elasticbeanstalk.com
Address: 13.234.120.45       <--- IP 1 (AZ A)
Address: 35.154.230.12       <--- IP 2 (AZ B)
```

---

## Proof 3: The AWS Console (The Visual Proof)

Take screenshots of your AWS Console to show the resources configured by Elastic Beanstalk:

### Screen A: Elastic Beanstalk Configuration
1. Go to **Elastic Beanstalk** in the AWS Console.
2. Click on **Configuration** on the left menu.
3. Show the **Capacity** card:
   - It will show **Environment type: Load balanced** instead of Single Instance.
   - It will show the Auto Scaling group settings (e.g., Min: 1, Max: 4).

### Screen B: EC2 Load Balancer
1. Go to the **EC2 Dashboard** in the AWS Console.
2. Scroll down on the left menu and click **Load Balancers**.
3. You will see an active Load Balancer (typically named with your environment ID) of type **application**.

/**
 * Hacker AI - Comprehensive Cyber Security Chatbot
 * Created by: Satyajit Sethy
 */

const knowledgeBase = {
    "information security": {
        definition: "Information Security protects systems, networks, and programs from digital attacks.\n\nKey areas:\n- Data protection\n- OS security (Windows/Linux)\n- Network security\n- Cloud security\n- Ethical hacking\n- Cryptography",
        related: ["ethical hacking", "network security", "cryptography"]
    },
    "ethical hacking": {
        definition: "Ethical hacking involves authorized penetration testing to identify vulnerabilities.\n\nPhases:\n1. Reconnaissance\n2. Scanning\n3. Gaining Access\n4. Maintaining Access\n5. Clearing Tracks\n\nTools: Kali Linux, Metasploit, Wireshark, Nmap",
        related: ["phases of hacking", "kali linux", "network security"]
    },
    "linux commands": {
        definition: `Essential Linux security commands:\n
# System Info
\`uname -a\` - System info
\`whoami\` - Current user

# File Permissions
\`chmod 700 file\` - Secure file
\`chown root:root file\` - Change owner

# Networking
\`netstat -tulnp\` - Open ports
\`iptables -L\` - Firewall rules`,
        related: ["linux permissions", "network security"]
    },
    "network security": {
        definition: "Network security protects infrastructure from threats.\n\nComponents:\n- Firewalls\n- IDS/IPS systems\n- VPNs\n- Encryption\n\nBest Practices:\n- Regular patching\n- Strong authentication\n- Network segmentation\n- Continuous monitoring",
        related: ["ethical hacking", "ip address", "cryptography"]
    },
    "cryptography": {
        definition: `Cryptography secures communication through encryption.

Types:
1. Symmetric (AES, DES) - Single key for encryption/decryption
2. Asymmetric (RSA, ECC) - Public/private key pair
3. Hashing (SHA-256, MD5) - One-way encryption

Example (MD5 Hash):
$ echo -n "password" | md5sum
5f4dcc3b5aa765d61d8327deb882cf99`,
        related: ["ethical hacking", "information security"]
    },
    "aws security": {
        definition: `AWS Security Best Practices:

1. IAM: Least privilege access
2. Encryption: KMS for data at rest
3. Network: Security Groups & NACLs
4. Monitoring: CloudTrail & GuardDuty
5. WAF: Web Application Firewall

Services: IAM, KMS, CloudHSM, Shield, GuardDuty`,
        related: ["information security", "cloud security"]
    },
    "phases of hacking": {
        definition: `5 Phases of Ethical Hacking:

1. Reconnaissance (Information Gathering)
   - Passive: Public sources (WHOIS, social media)
   - Active: Direct interaction (scanning)

2. Scanning
   - Port scanning (Nmap)
   - Vulnerability scanning (Nessus)

3. Gaining Access
   - Exploiting vulnerabilities
   - Password cracking

4. Maintaining Access
   - Backdoors
   - Rootkits

5. Covering Tracks
   - Log cleaning
   - Removing artifacts`,
        related: ["ethical hacking", "information security"]
    },
    "ip address classes": {
        definition: `IPv4 Address Classes:

Class A: 0.0.0.0 - 126.255.255.255 (N.H.H.H)
  - Subnet Mask: 255.0.0.0
  - Example: 10.0.0.1 (Private)

Class B: 128.0.0.0 - 191.255.255.255 (N.N.H.H)
  - Subnet Mask: 255.255.0.0
  - Example: 172.16.0.1 (Private)

Class C: 192.0.0.0 - 223.255.255.255 (N.N.N.H)
  - Subnet Mask: 255.255.255.0
  - Example: 192.168.1.1 (Private)

Class D: 224.0.0.0 - 239.255.255.255 (Multicast)
Class E: 240.0.0.0 - 255.255.255.255 (Experimental)`,
        related: ["network security", "subnetting"]
    },
    "linux permissions": {
        definition: `Linux File Permissions:

Permission Types:
- r (read) = 4
- w (write) = 2
- x (execute) = 1

Example:
$ ls -l file.txt
-rw-r--r-- 1 user group 0 Jan 1 00:00 file.txt

Breakdown:
- First character: File type (- for regular file)
- Next 3: Owner permissions (rw-)
- Next 3: Group permissions (r--)
- Last 3: Others permissions (r--)

Changing Permissions:
$ chmod 755 file.txt  # rwxr-xr-x
$ chmod u+x file.txt  # Add execute for owner
$ chmod go-w file.txt # Remove write for group/others`,
        related: ["linux commands", "user management"]
    },
    "subnetting": {
        definition: `Subnetting divides a network into smaller subnetworks.

Example (Class C: 192.168.1.0/24):

1. /25 (255.255.255.128):
   - Subnets: 2
   - Hosts per subnet: 126
   - Ranges:
     192.168.1.0 - 192.168.1.127
     192.168.1.128 - 192.168.1.255

2. /26 (255.255.255.192):
   - Subnets: 4
   - Hosts per subnet: 62
   - Ranges:
     192.168.1.0 - 192.168.1.63
     192.168.1.64 - 192.168.1.127
     192.168.1.128 - 192.168.1.191
     192.168.1.192 - 192.168.1.255`,
        related: ["ip address classes", "network security"]
    },
    "aws iam security": {
        definition: `AWS IAM Best Practices:

1. Use Groups to Assign Permissions
2. Grant Least Privilege
3. Enable MFA for Privileged Users
4. Use Access Keys Sparingly
5. Rotate Credentials Regularly
6. Use IAM Roles for EC2
7. Monitor Activity with CloudTrail

Example Policy:
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::example-bucket/*"
    }
  ]
}`,
        related: ["aws security", "cloud security"]
    },
    "ceaser cipher method": {
        definition: `Caesar Cipher Encryption Method:

Method: Shifting letters by a fixed number (key)

Example (Key = 3):
Plaintext:  A B C D E F G H I J K L M N O P Q R S T U V W X Y Z
Ciphertext: D E F G H I J K L M N O P Q R S T U V W X Y Z A B C

Encryption:
Plaintext:  HELLO
Ciphertext: KHOOR

Decryption:
Ciphertext: KHOOR
Plaintext:  HELLO`,
        related: ["cryptography", "encryption methods"]
    },
    "playfair cipher method": {
        definition: `Playfair Cipher Method:

1. Create a 5x5 matrix with a keyword (I and J share a cell)
2. Split plaintext into digraphs (pairs of letters)
3. Apply rules based on letter positions:
   - Same row: Shift right (circular)
   - Same column: Shift down (circular)
   - Rectangle: Swap with opposite corners

Example:
Keyword: MONARCHY
Matrix:
M O N A R
C H Y B D
E F G I/J K
L P Q S T
U V W X Z

Plaintext: HELLOWORLD → HE LL OW OR LD
Ciphertext: DM SX UR IA AE`,
        related: ["cryptography", "ceaser cipher method"]
    },
    "sam file security": {
        definition: `Windows SAM File Security:

- Location: C:\\Windows\\System32\\config\\SAM
- Stores user passwords in hash format (LM/NTLM)
- Protected by Windows system
- Can be extracted via:
  1. Offline NT Password & Registry Editor
  2. reg save hklm\\sam sam.hive
  3. Mimikatz tool

NTLM Hash Example:
Administrator:500:AAD3B435B51404EEAAD3B435B51404EE:31D6CFE0D16AE931B73C59D7E0C089C0:::

Cracking Methods:
1. Dictionary Attacks
2. Brute Force
3. Rainbow Tables`,
        related: ["windows security", "password cracking"]
    },
    "linux directory structure": {
        definition: `Linux Directory Structure:

/         - Root directory
/bin      - Essential user binaries
/boot     - Boot loader files
/dev      - Device files
/etc      - Configuration files
/home     - User home directories
/lib      - System libraries
/media    - Removable media
/mnt      - Temporary mount points
/opt      - Optional software
/proc     - Process information
/root     - Root user's home
/sbin     - System binaries
/tmp      - Temporary files
/usr      - User programs
/var      - Variable data (logs, etc.)`,
        related: ["linux commands", "linux administration"]
    },
    "dhcp server": {
        definition: `DHCP Server Configuration:

Purpose: Automatic IP address assignment

Process (DORA):
1. Discover - Client broadcasts for server
2. Offer - Server responds with IP offer
3. Request - Client requests offered IP
4. Acknowledge - Server confirms assignment

Linux Configuration:
1. Install package: dhcpd
2. Edit /etc/dhcp/dhcpd.conf:
   subnet 192.168.1.0 netmask 255.255.255.0 {
     range 192.168.1.100 192.168.1.200;
     option routers 192.168.1.1;
     option domain-name-servers 8.8.8.8;
   }
3. Start service: systemctl start dhcpd`,
        related: ["network security", "linux administration"]
    },
    "nmap": {
        definition: `🔥 Nmap (Network Mapper) - Ultimate Command Cheat Sheet

🔹 BASIC SCANS
\`nmap <target>\` → Scan top 1000 TCP ports
\`nmap -p- <target>\` → Scan ALL 65,535 ports
\`nmap -p 22,80,443 <target>\` → Scan specific ports
\`nmap -sn 192.168.1.0/24\` → Ping sweep (no port scan)

🔹 SCAN TECHNIQUES
\`nmap -sS <target>\` → Stealth SYN scan (default)
\`nmap -sT <target>\` → TCP connect scan
\`nmap -sU <target>\` → UDP port scan
\`nmap -sA <target>\` → TCP ACK scan (firewall test)

🔹 SERVICE DETECTION
\`nmap -sV <target>\` → Service version detection
\`nmap -O <target>\` → OS fingerprinting
\`nmap -A <target>\` → Aggressive scan (OS+services+traceroute)

🔹 SCRIPTING ENGINE
\`nmap --script=vuln <target>\` → Vulnerability scan
\`nmap --script=http-title <target>\` → Get webpage titles
\`nmap --script=ssl-enum-ciphers <target>\` → Check SSL ciphers

🔹 FIREWALL EVASION
\`nmap -f <target>\` → Fragment packets
\`nmap -D RND:10 <target>\` → Decoy scan (hide among fake IPs)
\`nmap --source-port 53 <target>\` → Spoof source port
\`nmap --data-length 100 <target>\` → Add random data

🔹 OUTPUT FORMATS
\`nmap -oN scan.txt <target>\` → Normal output
\`nmap -oX scan.xml <target>\` → XML format
\`nmap -oG scan.gnmap <target>\` → Grepable format

⚠ LEGAL NOTE: Only scan networks you own or have permission to test!`,
        related: ["ethical hacking", "network security", "phases of hacking"]
    }
};

// Enhanced chat functionality
const chatMessages = document.getElementById('chat-messages');
const userInput = document.getElementById('user-input');

function addMessage(text, isUser) {
    const messageDiv = document.createElement('div');
    messageDiv.className = `message ${isUser ? 'user-message' : 'bot-message'}`;
    
    // Format code blocks and lists
    let formattedText = text;
    
    // Format code blocks (text between backticks)
    formattedText = formattedText.replace(/`([^`]+)`/g, '<code>$1</code>');
    
    // Format multi-line code blocks
    formattedText = formattedText.replace(/```([^`]+)```/gs, '<pre>$1</pre>');
    
    // Format lists
    formattedText = formattedText.replace(/^\s*-\s*(.+)$/gm, '<li>$1</li>');
    formattedText = formattedText.replace(/^\s*\d+\.\s*(.+)$/gm, '<li>$1</li>');
    formattedText = formattedText.replace(/<li>.*<\/li>/gs, '<ul>$&</ul>');
    
    const time = new Date().toLocaleTimeString([], {hour: '2-digit', minute:'2-digit'});
    messageDiv.innerHTML = `${formattedText.replace(/\n/g, '<br>')}<span class="message-time">${time}</span>`;
    chatMessages.appendChild(messageDiv);
    chatMessages.scrollTop = chatMessages.scrollHeight;
}

function showTyping() {
    const typingDiv = document.createElement('div');
    typingDiv.className = 'typing-indicator';
    typingDiv.innerHTML = `<div class="typing-dot"></div><div class="typing-dot"></div><div class="typing-dot"></div>`;
    chatMessages.appendChild(typingDiv);
    chatMessages.scrollTop = chatMessages.scrollHeight;
    return typingDiv;
}

function hideTyping(typingDiv) {
    typingDiv?.remove();
}

function processInput(input) {
    input = input.toLowerCase().trim();
    
    // Help command
    if (input === 'help') {
        return `I can help with these Cyber Security topics:
- Ethical Hacking (phases, tools)
- Linux Administration (commands, permissions)
- Network Security (subnetting, protocols)
- Cryptography (encryption methods)
- AWS Security (IAM, best practices)
- Windows Security (SAM file, password cracking)
- Nmap (port scanning techniques)

Try asking about any of these topics or use the quick replies below!`;
    }
    
    // Check knowledge base
    for (const topic in knowledgeBase) {
        if (input.includes(topic)) {
            let response = `<strong>${topic.toUpperCase()}</strong><br><br>${knowledgeBase[topic].definition}`;
            if (knowledgeBase[topic].related) {
                response += `<br><br><em>Related topics: ${knowledgeBase[topic].related.join(', ')}</em>`;
            }
            return response;
        }
    }
    
    // Default response
    return `I specialize in Cyber Security topics. Try asking about:
- Ethical hacking techniques
- Linux security commands
- Network protection methods
- Cryptographic algorithms
- AWS security best practices
- Windows security (SAM file)
- Nmap scanning commands

Or type 'help' for more options.`;
}

function sendMessage() {
    const message = userInput.value.trim();
    if (!message) return;
    
    addMessage(message, true);
    userInput.value = '';
    
    const typing = showTyping();
    
    setTimeout(() => {
        hideTyping(typing);
        const response = processInput(message);
        addMessage(response, false);
    }, 1000 + Math.random() * 1500);
}

function sendQuickReply(message) {
    userInput.value = message;
    sendMessage();
}

function handleKeyPress(e) {
    if (e.key === 'Enter') sendMessage();
}

// Initial welcome
setTimeout(() => {
    addMessage("Type 'help' to see Cyber Security topics I can explain, or ask your question directly!", false);
}, 1500);

// Add right-click context menu for code copying
document.addEventListener('contextmenu', (e) => {
    if (e.target.tagName === 'CODE' || e.target.tagName === 'PRE') {
        e.preventDefault();
        const range = document.createRange();
        range.selectNode(e.target);
        window.getSelection().removeAllRanges();
        window.getSelection().addRange(range);
        document.execCommand('copy');
        
        // Show copied notification
        const notification = document.createElement('div');
        notification.textContent = 'Copied to clipboard!';
        notification.style.position = 'fixed';
        notification.style.bottom = '20px';
        notification.style.right = '20px';
        notification.style.backgroundColor = 'var(--secondary)';
        notification.style.color = 'white';
        notification.style.padding = '10px';
        notification.style.borderRadius = '5px';
        notification.style.zIndex = '1000';
        document.body.appendChild(notification);
        
        setTimeout(() => {
            notification.remove();
        }, 2000);
    }
});

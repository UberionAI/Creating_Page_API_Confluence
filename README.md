# Creating_Page_API_Confluence

This tool allows you to:

- Connect to a virtual machine (VM) via SSH
- Execute a long one-liner (or list of commands) as `sudo`
- Collect system information
- Convert the result to HTML (Confluence Storage format)
- Create or update a Confluence page with this report

---

## ⚙️ Installation

1. Make sure **Go** (1.18+) is installed
2. Clone the repository:
   ```bash
   git clone https://github.com/UberionAI/Creating_Page_API_Confluence
   cd Creating_Page_API_Confluence
   ```
3. Install dependencies:
   ```bash
   go mod tidy
   ```

---

## 📝 `.env` Configuration

Create a `.env` file in the project root with the following content:

```env
# SSH access to the VM
SSH_USERNAME=username
SSH_PASSWORD=password
SSH_SUDO_PASSWORD=sudo_password
SSH_HOSTNAME=vm_ip_or_hostname

# Confluence access
CONFLUENCE_IP=confluence_host:port
CONFLUENCE_USER=username
CONFLUENCE_PASSWORD=password
CONFLUENCE_SPACE=space_key
```

> ⚠️ All fields are required. The program will not run without them.

---

## 📋 Preparing Commands

There are two options:

### Option 1 — use `commands.txt`

Create a `commands.txt` file with a list of commands (each with `echo '###TAG' ; command`):

```bash
echo '###HOSTNAME' ; hostname
echo '###OS' ; cat /etc/os-release | grep PRETTY_NAME | cut -d= -f2 | tr -d '"' || true
echo '###VCPU' ; nproc || true
echo '###RAM' ; free -h | awk '/Mem:/{print $2}' || true
echo '###DISK_TOTAL' ; lsblk -b -d -o SIZE -n | awk '{s+=$1} END{printf "%.0fG\n", s/1024/1024/1024}'
...
```

### Option 2 — pass commands as an argument

You can pass commands directly to the `--commands` argument (separated by `;`):

```bash
go run main.go --commands "echo '###HOSTNAME' ; hostname ; echo '###OS' ; cat /etc/os-release"
```

> 💡 If neither `--commands` nor `--command-file` are provided, a **default built-in set of commands** will be used.

---

## 🚀 Running

### Using `commands.txt`

```bash
go run main.go --command-file commands.txt --env .env
```

### Passing commands directly

```bash
go run main.go --commands "echo '###HOSTNAME' ; hostname" --env .env
```

### With a custom Confluence page title

```bash
go run main.go --command-file commands.txt --title "VM Report" --env .env
```

After execution, the program will output the URL of the created or updated Confluence page:

```
Confluence page created/updated: http://<host>/pages/viewpage.action?pageId=123456
```

---

## 📑 What the script does

- Connects to the VM via SSH (with login and password)
- Runs commands as `sudo`
- Each section starts with `###TAG`
- Splits output by tags and builds HTML tables and code blocks
- Uploads the result to Confluence (creates or updates a page by title)

---

## 📌 Example result in Confluence

**Page title:** `VM Passport: my-vm`

**Content:**

- Basic info (hostname, distro, IP)
- Hardware specs (CPU, RAM, disks)
- Network interfaces
- Routing table
- IPTables
- lsblk, df -h
- Active / inactive services
- System users
- Report timestamp

---

## ⚡ Tips

- Double-check your `.env`
- Make sure the user has `sudo` rights without `tty`
- Make sure the Confluence user has permission to create pages in the target space

---

## 📄 License

MIT


# CrowdStrike Custom IOM Toolkit

A comprehensive toolkit for managing Custom Indicators of Misconfiguration (IOMs) in CrowdStrike CSPM environments. This tool provides both graphical and command-line interfaces for creating, testing, and managing custom security policies.

## Features

- **Dual Interface**: GUI mode (default) and CLI mode with `--cli` flag
- **Policy Management**: Create, update, delete, and view custom IOM policies
- **Interactive Policy Testing**: Test policies against live cloud assets
- **Multi-Cloud Support**: AWS, GCP, and Azure resource types
- **Rego Policy Editor**: Built-in editor with syntax helpers and templates
- **Asset Data Export**: Export sample asset data for policy development
- **Cross-Platform**: Optimized for macOS ARM64 (Apple Silicon), source code supports all platforms

## Installation

### Option 1: Download Pre-built Executable (Recommended)

Download the latest release for macOS ARM64 from the [Releases](https://github.com/kuhnskc/cspm-iom-toolkit/releases) page:

- **macOS ARM64**: `CrowdStrikeIOMToolkit-macos-arm64`

Make the file executable:
```bash
chmod +x CrowdStrikeIOMToolkit-macos-arm64
```

**Note:** This toolkit is specifically built for macOS ARM64 (Apple Silicon) machines. For other platforms or Intel Macs, please use Option 2 (Run from Source) below.

### macOS Security Warning

When running the macOS executable, you may see a security warning: *"CrowdStrikeIOMToolkit-macos-arm64 cannot be opened because it is from an unidentified developer."*

This is normal for unsigned applications. To safely run the toolkit:

**Method 1: Right-click Override**
1. Right-click (or Control+click) on `CrowdStrikeIOMToolkit-macos-arm64`
2. Select **"Open"** from the context menu
3. Click **"Open"** in the warning dialog
4. The app will run and be remembered as safe

**Method 2: System Preferences**
1. Try to run the app normally (it will be blocked)
2. Go to **System Preferences > Security & Privacy > General**
3. Click **"Open Anyway"** next to the blocked app message
4. Confirm by clicking **"Open"**

**Method 3: Command Line**
```bash
# Remove quarantine and make executable
xattr -d com.apple.quarantine CrowdStrikeIOMToolkit-macos-arm64
chmod +x CrowdStrikeIOMToolkit-macos-arm64
./CrowdStrikeIOMToolkit-macos-arm64
```

This warning appears because the executable is not code-signed by an Apple Developer. The software is safe to use.

### Option 2: Run from Source

```bash
git clone https://github.com/kuhnskc/cspm-iom-toolkit.git
cd cspm-iom-toolkit
pip install -r requirements.txt
python custom_iom_toolkit.py
```

### Virtual Environment Setup (Recommended for Source Installation)

To avoid dependency conflicts, it's recommended to use a Python virtual environment:

**Using venv (Python 3.3+):**
```bash
# Clone and navigate to project
git clone https://github.com/kuhnskc/cspm-iom-toolkit.git
cd cspm-iom-toolkit

# Create virtual environment
python -m venv venv

# Activate virtual environment
# On macOS/Linux:
source venv/bin/activate
# On Windows:
venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Run the application
python custom_iom_toolkit.py

# To deactivate when done
deactivate
```

**Using conda:**
```bash
# Create conda environment
conda create -n cspm-toolkit python=3.9
conda activate cspm-toolkit

# Clone and install
git clone https://github.com/kuhnskc/cspm-iom-toolkit.git
cd cspm-iom-toolkit
pip install -r requirements.txt

# Run the application
python custom_iom_toolkit.py
```

**Benefits of Virtual Environments:**
- Isolates project dependencies from system Python
- Prevents version conflicts with other Python projects
- Makes dependency management cleaner and more predictable
- Recommended best practice for Python development

## CrowdStrike API Setup

### Required API Scopes

Create a new API client in your CrowdStrike console with these scopes:

**Required Scopes:**
- `CSPM registration: Read, Write`
- `Cloud Security Assessment: Read`

**API Client Setup:**
1. Log into your CrowdStrike console
2. Navigate to **Support > API Clients and Keys**
3. Click **Add new API client**
4. Provide a name: "Custom IOM Toolkit"
5. Add the required scopes listed above
6. Click **Add** and save your Client ID and Client Secret

### Authentication Methods

**Method 1: Environment Variables (Recommended)**
```bash
export FALCON_CLIENT_ID="your_client_id"
export FALCON_CLIENT_SECRET="your_client_secret"
export FALCON_BASE_URL="https://api.crowdstrike.com"  # or your cloud URL
```

**Method 2: Interactive Credential Entry**

The toolkit will prompt for credentials if environment variables are not set.

### Cloud Environment URLs

- **US-1**: `https://api.crowdstrike.com`
- **US-2**: `https://api.us-2.crowdstrike.com`
- **EU-1**: `https://api.eu-1.crowdstrike.com`
- **US-GOV-1**: `https://api.laggar.gcw.crowdstrike.com`

## Usage

### GUI Mode (Default)

```bash
# Using executable
./CrowdStrikeIOMToolkit-macos-arm64

# Using Python
python custom_iom_toolkit.py
```

### CLI Mode

```bash
# Using executable
./CrowdStrikeIOMToolkit-macos-arm64 --cli

# Using Python
python custom_iom_toolkit.py --cli
```

## Main Features

### Policy Management
- **View Policies**: List and examine existing custom policies
- **Create Policies**: Step-by-step policy creation wizard
- **Edit Policies**: Modify descriptions, severity, alerts, and Rego logic
- **Delete Policies**: Remove unwanted policies with confirmation
- **Test Policies**: Validate policy logic against live cloud assets

### Policy Testing
The toolkit can test your Rego policies against real assets in your environment:
- Tests against up to 3 active assets for performance
- Shows pass/fail results with detailed analysis
- Provides policy behavior interpretation
- Helps validate policy logic before deployment

### Asset Data Export
Export sample asset configurations to understand data structures:
- Fetches live asset data from your CSPM environment
- Exports to JSON format for policy development
- Shows available fields for Rego policy writing

## Policy Creation Workflow

1. **Basic Information**: Name and description
2. **Resource Type**: Select target cloud resource type
3. **Sample Data**: Optional - fetch sample asset data for reference
4. **Severity Level**: Critical (0) to Informational (3)
5. **Alert Information**: User-facing violation messages
6. **Remediation Steps**: Step-by-step fix instructions
7. **Rego Logic**: Write the policy evaluation logic
8. **Testing**: Test against live assets before creation

## Rego Policy Development

The toolkit includes:
- **Syntax Templates**: Pre-built Rego templates for common patterns
- **Code Formatting**: Automatic indentation and structure
- **Testing Integration**: Test policies before saving
- **Asset Data Access**: Sample real asset data for policy development

### Rego Format Requirements

```rego
package crowdstrike

# Required default result
default result = "pass"

# Policy logic
result = "fail" if {
    input.resource_type == "AWS::S3::Bucket"
    # Your violation conditions
}
```

## Alert and Remediation Format

Use pipe-separated format for automatic numbering:

**Alert Info**: `Security issue detected|Resource violates policy|Immediate attention required`

**Remediation**: `Navigate to AWS Console|Fix the configuration|Verify changes|Document action`

CrowdStrike automatically converts these to numbered lists in the console.

## Building from Source

To create your own executable:

```bash
pip install pyinstaller
pyinstaller toolkit.spec
```

The executable will be created in the `dist/` directory.

## Support

For issues related to:
- **CrowdStrike API**: Contact CrowdStrike support
- **Tool Usage**: Check policy syntax and API connectivity
- **Policy Logic**: Refer to [Open Policy Agent Rego documentation](https://www.openpolicyagent.org/docs/latest/policy-language/)

## License

This project is provided as-is for CrowdStrike customers to manage their custom IOM policies.
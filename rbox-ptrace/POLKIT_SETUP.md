# PolicyKit Integration for ReadOnlyBox Ptrace

This document describes the optional PolicyKit (polkit) integration for readonlybox-ptrace.

## Overview

The ptrace client can request elevated privileges through PolicyKit's `pkexec` command. This works **without any installation** - the policy file is optional and only enhances the authentication dialog.

## How It Works

When readonlybox-ptrace runs without ptrace capabilities:

1. **With pkexec**: Shows an authentication dialog (generic or custom if policy file present)
2. **Without pkexec**: Falls back to sudo or displays an error with instructions

## Usage (No Installation Required)

Simply run the ptrace client - it will automatically request privileges:

```bash
./readonlybox-ptrace wrap bash
```

If you don't have ptrace capabilities, you'll see an authentication dialog (if pkexec is available) or an error message suggesting to use sudo.

## Optional Policy File

The `readonlybox-ptrace.policy` file provides a **customized** authentication dialog with:
- Better description of what the program does
- Custom icon
- Configurable authorization rules

Without the policy file, pkexec uses a generic "Authentication required" dialog.

### To Enable Custom Dialog (Optional)

If you want the customized authentication dialog, the policy file must be installed system-wide:

```bash
sudo cp readonlybox-ptrace.policy /usr/share/polkit-1/actions/org.freedesktop.policykit.pkexec.readonlybox-ptrace.policy
```

**Note**: This is purely cosmetic - the program works the same with or without the policy file.

## Alternative Authentication Methods

### Method 1: sudo (No Setup)

```bash
sudo ./readonlybox-ptrace wrap bash
```

### Method 2: setcap (One-time Setup)

```bash
sudo setcap cap_sys_ptrace+eip ./readonlybox-ptrace
./readonlybox-ptrace wrap bash  # Now works without sudo
```

### Method 3: pkexec (Automatic)

```bash
./readonlybox-ptrace wrap bash  # Automatic privilege request
```

## How the Client Handles Missing Capabilities

1. **First**: Checks if it has CAP_SYS_PTRACE
2. **If not**: Attempts to use `pkexec` for automatic privilege escalation
3. **If pkexec fails**: Displays error with instructions to use sudo or setcap

## Desktop Environment Support

PolicyKit authentication dialogs work on:

- **GNOME**: polkit-gnome-authentication-agent-1
- **KDE**: polkit-kde-authentication-agent-1
- **XFCE**: polkit-gnome-authentication-agent-1
- **MATE**: polkit-mate-authentication-agent-1
- **Cinnamon**: polkit-gnome-authentication-agent-1

## Troubleshooting

### "Cannot use ptrace: Operation not permitted"

Use sudo:
```bash
sudo ./readonlybox-ptrace wrap <command>
```

Or set capabilities:
```bash
sudo setcap cap_sys_ptrace+eip ./readonlybox-ptrace
```

### "pkexec: command not found"

PolicyKit is not installed. Use sudo instead:
```bash
sudo ./readonlybox-ptrace wrap bash
```

### Generic Authentication Dialog

The policy file is not installed. To get the custom dialog:
```bash
sudo cp readonlybox-ptrace.policy /usr/share/polkit-1/actions/
```

## Security Considerations

- pkexec provides temporary privilege escalation with user consent
- sudo provides explicit user control
- setcap provides transparent operation but requires one-time root setup
- All methods maintain the same security model (commands still validated by server)

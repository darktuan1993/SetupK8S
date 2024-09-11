apt install net-tools ntp wget curl jq  sysstat traceroute libpam-pwquality cifs-utils rsyslog htop ca-certificates nfs-common sudo -y
apt-get remove prelink talk -y
apt-get remove vsftpd -y


# Tuning SSH

echo "IgnoreRhosts yes" > /etc/ssh/sshd_config
echo "HostbasedAuthentication no" >> /etc/ssh/sshd_config
echo "PermitUserEnvironment no" >>  /etc/ssh/sshd_config
echo "PermitEmptyPasswords no" >> /etc/ssh/sshd_config
echo "PermitRootLogin yes" >> /etc/ssh/sshd_config
echo "MaxAuthTries 4 " >> /etc/ssh/sshd_config
echo "X11Forwarding no" >> /etc/ssh/sshd_config
echo "AllowTcpForwarding no" >> /etc/ssh/sshd_config
echo "MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256" >> /etc/ssh/sshd_config
echo "Banner /etc/issue.net" >> /etc/ssh/sshd_config
echo "MaxStartups 10:30:60" >> /etc/ssh/sshd_config
echo "LoginGraceTime 60" >> /etc/ssh/sshd_config
echo "ClientAliveInterval 15" >> /etc/ssh/sshd_config
echo "ClientAliveCountMax 3" >> /etc/ssh/sshd_config

echo "Có thì xóa không có thì thôi"
sudo rm /etc/hosts.equiv
sudo rm /etc/shosts.equiv
rm ~/.rhosts
rm ~/.shosts


sudo getent passwd | awk -F: '{ print $1}' | uniq -d



# Enable CMD log
echo "export PROMPT_COMMAND='RETRN_VAL=$?;logger -p local6.debug \"\$(whoami) [\$\$]: \$(history 1 | sed \"s/[ ][0-9]+[ ]//\") [\$RETRN_VAL]\"' " >> /etc/bash.bashrc
# Setting giờ của log command
echo "$ActionFileDefaultTemplate RSYSLOG_TraditionalFileFormat" >> /etc/rsyslog.d/bash.conf
echo "local6.* /var/log/commands.log" >> /etc/rsyslog.d/bash.conf
echo "/var/log/commands.log" >> /etc/logrotate.d/rsyslog
echo "root" >> /etc/cron.allow


#!/bin/bash

# Define variables
FSTAB_FILE="/etc/fstab"
TMP_MOUNT="/tmp"
MOUNT_OPTIONS="defaults,rw,nosuid,nodev,noexec,relatime"
MOUNT_OPTIONS_HOME="defaults,rw,nosuid,nodev,relatime"
MOUNT_OPTIONS_VAR="defaults,rw,nosuid,nodev,relatime"
# Check if /tmp is already in /etc/fstab
if grep -q "$TMP_MOUNT" "$FSTAB_FILE"; then
    echo "Updating /tmp entry in $FSTAB_FILE..."
    
    # Backup fstab before editing
    cp "$FSTAB_FILE" "${FSTAB_FILE}.bak"
    
    # Use sed to update the mount options for /tmp
    sed -i "/\s\/tmp\s/ s/defaults.*/$MOUNT_OPTIONS 0 0/" "$FSTAB_FILE"
    sed -i "/\s\/home\s/ s/defaults.*/$MOUNT_OPTIONS_HOME 0 0/" "$FSTAB_FILE"
    sed -i "/\s\/var\s/ s/defaults.*/$MOUNT_OPTIONS_VAR 0 0/" "$FSTAB_FILE"
    sed -i "/\s\/var/log\s/ s/defaults.*/$MOUNT_OPTIONS_VAR 0 0/" "$FSTAB_FILE"
    sed -i "/\s\/var/tmp\s/ s/defaults.*/$MOUNT_OPTIONS 0 0/" "$FSTAB_FILE"
    sed -i "/\s\/var/log/audit\s/ s/defaults.*/$MOUNT_OPTIONS 0 0/" "$FSTAB_FILE"    
    echo "tmpfs /dev/shm tmpfs defaults,rw,nosuid,nodev,noexec,relatime 0 0" >> $FSTAB_FILE
    echo "/tmp entry updated successfully."
else
    echo "/tmp partition not found in $FSTAB_FILE. Please add it manually."
    exit 1
fi

# Remount /tmp with the new options
echo "Remounting /tmp with new options..."
mount -o remount /tmp

if [ $? -eq 0 ]; then
    echo "/tmp remounted successfully with new options."
else
    echo "Failed to remount /tmp. Please check the fstab file for errors."
    exit 1
fi

################  Apport #################
#!/bin/bash

# Function to edit /etc/default/apport and set enabled=0
edit_apport_config() {
    APPORT_CONFIG="/etc/default/apport"
    echo "Editing $APPORT_CONFIG to disable apport..."
    
    if grep -q "^enabled=" "$APPORT_CONFIG"; then
        # If 'enabled=' exists, replace it with 'enabled=0'
        sudo sed -i 's/^enabled=.*/enabled=0/' "$APPORT_CONFIG"
    else
        # If 'enabled=' doesn't exist, add it at the end
        echo "enabled=0" | sudo tee -a "$APPORT_CONFIG"
    fi
    
    echo "$APPORT_CONFIG updated successfully."
}

# Function to stop and disable apport service
stop_and_disable_apport_service() {
    echo "Stopping and disabling apport service..."
    sudo systemctl stop apport.service
    sudo systemctl --now disable apport.service
    
    if [ $? -eq 0 ]; then
        echo "Apport service stopped and disabled successfully."
    else
        echo "Failed to stop or disable apport service."
        exit 1
    fi
}

# Function to remove apport package
purge_apport_package() {
    echo "Purging apport package..."
    sudo apt purge -y apport
    
    if [ $? -eq 0 ]; then
        echo "Apport package removed successfully."
    else
        echo "Failed to remove apport package."
        exit 1
    fi
}

# Main logic
echo "Choose an option:"
echo "1) Disable apport by editing /etc/default/apport and stopping the service"
echo "2) Remove apport package"

read -p "Enter your choice (1 or 2): " choice

case $choice in
    1)
        edit_apport_config
        stop_and_disable_apport_service
    ;;
    2)
        purge_apport_package
    ;;
    *)
        echo "Invalid choice. Please run the script again and choose 1 or 2."
        exit 1
    ;;
esac


# Function to add or modify the line in /etc/security/limits.conf
modify_limits_conf() {
    LIMITS_FILE="/etc/security/limits.conf"
    LIMITS_LINE="* hard core 0"
    
    echo "Adding '$LIMITS_LINE' to $LIMITS_FILE..."
    if grep -q "^* hard core" "$LIMITS_FILE"; then
        sudo sed -i 's/^* hard core.*/'"$LIMITS_LINE"'/' "$LIMITS_FILE"
    else
        echo "$LIMITS_LINE" | sudo tee -a "$LIMITS_FILE"
    fi
    echo "Updated $LIMITS_FILE successfully."
}

# Function to add or modify the parameter in /etc/sysctl.conf
modify_sysctl_conf() {
    SYSCTL_FILE="/etc/sysctl.conf"
    SYSCTL_PARAM="fs.suid_dumpable = 0"
    
    echo "Adding '$SYSCTL_PARAM' to $SYSCTL_FILE..."
    if grep -q "^fs.suid_dumpable" "$SYSCTL_FILE"; then
        sudo sed -i 's/^fs.suid_dumpable.*/'"$SYSCTL_PARAM"'/' "$SYSCTL_FILE"
    else
        echo "$SYSCTL_PARAM" | sudo tee -a "$SYSCTL_FILE"
    fi
    
    # Apply the kernel parameter change
    sudo sysctl -w fs.suid_dumpable=0
    echo "fs.suid_dumpable set to 0 and changes applied."
}

# Function to modify /etc/systemd/coredump.conf if systemd-coredump is installed
modify_coredump_conf() {
    COREDUMP_FILE="/etc/systemd/coredump.conf"
    
    if command -v systemctl &> /dev/null && systemctl list-units --type=service | grep -q 'systemd-coredump'; then
        echo "Modifying $COREDUMP_FILE..."
        
        # Add/modify lines in coredump.conf
        sudo sed -i '/^Storage=/d' "$COREDUMP_FILE"
        sudo sed -i '/^ProcessSizeMax=/d' "$COREDUMP_FILE"
        
        echo "Storage=none" | sudo tee -a "$COREDUMP_FILE"
        echo "ProcessSizeMax=0" | sudo tee -a "$COREDUMP_FILE"
        
        # Reload systemd
        sudo systemctl daemon-reload
        echo "systemd daemon reloaded successfully."
    else
        echo "systemd-coredump is not installed, skipping coredump configuration."
    fi
}

# Main script execution
modify_limits_conf
modify_sysctl_conf
modify_coredump_conf

echo "Remediation completed successfully."


#!/bin/bash

# Define the grub configuration file path
GRUB_CFG="/boot/grub/grub.cfg"

# Function to set ownership and permissions
set_grub_permissions() {
    echo "Setting ownership to root:root for $GRUB_CFG..."
    sudo chown root:root "$GRUB_CFG"
    
    echo "Setting permissions to u-wx,go-rwx for $GRUB_CFG..."
    sudo chmod u-wx,go-rwx "$GRUB_CFG"
    
    # Verify the changes
    if [ $? -eq 0 ]; then
        echo "Permissions and ownership updated successfully for $GRUB_CFG."
    else
        echo "Failed to update permissions or ownership for $GRUB_CFG."
        exit 1
    fi
}

# Main script execution



#########################
#!/bin/bash

# Function to implement loopback rules for UFW
implement_loopback_rules() {
    echo "Allowing incoming traffic on loopback (lo) interface..."
    sudo ufw allow in on lo
    
    echo "Allowing outgoing traffic on loopback (lo) interface..."
    sudo ufw allow out on lo
    
    echo "Denying incoming traffic from IPv4 loopback range 127.0.0.0/8..."
    sudo ufw deny in from 127.0.0.0/8
    
    echo "Denying incoming traffic from IPv6 loopback range ::1..."
    sudo ufw deny in from ::1
    
    echo "Loopback rules applied successfully."
}

# Check if UFW is installed and enabled
if command -v ufw &> /dev/null; then
    echo "UFW is installed."
    
    # Apply loopback rules
    implement_loopback_rules
else
    echo "UFW is not installed. Please install UFW and try again."
    exit 1
fi
apt install nftables -y
systemctl start nftables
systemctl enable nftables

apt install auditd audispd-plugins
systemctl start auditd
systemctl --now enable auditd
#!/bin/bash

# Function to implement loopback rules using iptables
implement_loopback_rules() {
    echo "Allowing incoming traffic on loopback interface (lo)..."
    sudo iptables -A INPUT -i lo -j ACCEPT
    
    echo "Allowing outgoing traffic on loopback interface (lo)..."
    sudo iptables -A OUTPUT -o lo -j ACCEPT
    
    echo "Dropping incoming traffic from the IPv4 loopback range (127.0.0.0/8)..."
    sudo iptables -A INPUT -s 127.0.0.0/8 -j DROP
    
    echo "Loopback rules applied successfully."
}

# Check if iptables is installed and running
if command -v iptables &> /dev/null; then
    echo "iptables is installed."
    
    # Apply loopback rules
    implement_loopback_rules
else
    echo "iptables is not installed. Please install iptables and try again."
    exit 1
fi



#!/bin/bash

# Define the grub file location
GRUB_FILE="/etc/default/grub"

# Define the parameters to add
PARAMETERS="apparmor=1 security=apparmor audit=1 audit_backlog_limit=8192"

# Function to modify /etc/default/grub
modify_grub_config() {
    echo "Modifying $GRUB_FILE..."
    
    # Check if GRUB_CMDLINE_LINUX exists
    if grep -q '^GRUB_CMDLINE_LINUX=' "$GRUB_FILE"; then
        # Append parameters to the GRUB_CMDLINE_LINUX line if they don't exist
        sudo sed -i "/^GRUB_CMDLINE_LINUX=/ s/\"\$/ $PARAMETERS\"/" "$GRUB_FILE"
        echo "Added $PARAMETERS to GRUB_CMDLINE_LINUX in $GRUB_FILE."
    else
        echo "GRUB_CMDLINE_LINUX is not found in $GRUB_FILE. Please check the file."
        exit 1
    fi
}

# Function to update GRUB
update_grub_config() {
    echo "Updating GRUB configuration..."
    sudo update-grub
    
    if [ $? -eq 0 ]; then
        echo "GRUB configuration updated successfully."
    else
        echo "Failed to update GRUB configuration."
        exit 1
    fi
}






#!/bin/bash

# Define the auditd configuration file
AUDITD_CONF="/etc/audit/auditd.conf"

# Function to set max_log_file_action = keep_logs
set_auditd_max_log_action() {
    echo "Modifying $AUDITD_CONF to set max_log_file_action to keep_logs..."
    
    # Check if the parameter exists, and modify it if necessary
    if grep -q "^max_log_file_action" "$AUDITD_CONF"; then
        sudo sed -i 's/^max_log_file_action.*/max_log_file_action = keep_logs/' "$AUDITD_CONF"
    else
        echo "max_log_file_action = keep_logs" | sudo tee -a "$AUDITD_CONF"
    fi
    
    echo "Auditd configuration updated successfully."
}

# Check if auditd is installed
if command -v auditd &> /dev/null; then
    # Apply the configuration change
    set_auditd_max_log_action
else
    echo "auditd is not installed. Please install auditd and try again."
    exit 1
fi


#!/bin/bash

# Define the auditd configuration file
AUDITD_CONF="/etc/audit/auditd.conf"

# Function to set auditd parameters
set_auditd_parameters() {
    echo "Modifying $AUDITD_CONF with the required parameters..."
    
    # Modify or add max_log_file_action = keep_logs
    if grep -q "^max_log_file_action" "$AUDITD_CONF"; then
        sudo sed -i 's/^max_log_file_action.*/max_log_file_action = keep_logs/' "$AUDITD_CONF"
    else
        echo "max_log_file_action = keep_logs" | sudo tee -a "$AUDITD_CONF"
    fi
    
    # Modify or add space_left_action = email
    if grep -q "^space_left_action" "$AUDITD_CONF"; then
        sudo sed -i 's/^space_left_action.*/space_left_action = email/' "$AUDITD_CONF"
    else
        echo "space_left_action = email" | sudo tee -a "$AUDITD_CONF"
    fi
    
    # Modify or add action_mail_acct = root
    if grep -q "^action_mail_acct" "$AUDITD_CONF"; then
        sudo sed -i 's/^action_mail_acct.*/action_mail_acct = root/' "$AUDITD_CONF"
    else
        echo "action_mail_acct = root" | sudo tee -a "$AUDITD_CONF"
    fi
    
    # Modify or add admin_space_left_action = halt
    if grep -q "^admin_space_left_action" "$AUDITD_CONF"; then
        sudo sed -i 's/^admin_space_left_action.*/admin_space_left_action = halt/' "$AUDITD_CONF"
    else
        echo "admin_space_left_action = halt" | sudo tee -a "$AUDITD_CONF"
    fi
    
    echo "Auditd configuration updated successfully."
}

# Check if auditd is installed
if command -v auditd &> /dev/null; then
    # Apply the configuration changes
    set_auditd_parameters
else
    echo "auditd is not installed. Please install auditd and try again."
    exit 1
fi




########################################################################
#!/bin/bash

# Define the audit rules files
SCOPE_RULES_FILE="/etc/audit/rules.d/50-scope.rules"
USER_EMULATION_RULES_FILE="/etc/audit/rules.d/50-user_emulation.rules"
TIME_CHANGE_RULES_FILE="/etc/audit/rules.d/50-time-change.rules"
NETWORK_ENV_RULES_FILE="/etc/audit/rules.d/50-system_local.rules"
IDENTITY_RULES_FILE="/etc/audit/rules.d/50-identity.rules"
SESSION_RULES_FILE="/etc/audit/rules.d/50-session.rules"
LOGIN_RULES_FILE="/etc/audit/rules.d/50-login.rules"
MAC_POLICY_RULES_FILE="/etc/audit/rules.d/50-MAC-policy.rules"
FINALIZE_RULES_FILE="/etc/audit/rules.d/99-finalize.rules"
SUDOERS_FILE="/etc/sudoers"
SUDOERS_LOGFILE_ENTRY='Defaults logfile="/var/log/sudo.log"'
FSTAB_FILE="/etc/fstab"
JOURNALD_CONF="/etc/systemd/journald.conf"
PAM_PASSWORD_FILE="/etc/pam.d/common-password"
PAM_PASSWORD_ENTRY="password [success=1 default=ignore] pam_unix.so obscure use_authtok try_first_pass yescrypt remember=5"
COMMON_AUTH_FILE="/etc/pam.d/common-auth"
COMMON_ACCOUNT_FILE="/etc/pam.d/common-account"
FAILLOCK_CONF_FILE="/etc/security/faillock.conf"
COMMON_PASSWORD_FILE="/etc/pam.d/common-password"
LOGIN_DEFS_FILE="/etc/login.defs"
PASS_MAX_DAYS_VALUE=365

# Backup function for sensitive files
backup_file_login_day() {
    local file_path="$1"
    echo "Backing up $file_path..."
    sudo cp "$file_path" "${file_path}.bak"
    if [ $? -eq 0 ]; then
        echo "Backup of $file_path created at ${file_path}.bak"
    else
        echo "Failed to create backup of $file_path."
        exit 1
    fi
}

# Function to modify /etc/login.defs to set PASS_MAX_DAYS
set_pass_max_days() {
    echo "Configuring $LOGIN_DEFS_FILE to set PASS_MAX_DAYS to $PASS_MAX_DAYS_VALUE..."

    # Backup the file
    backup_file_login_day "$LOGIN_DEFS_FILE"

    # Ensure PASS_MAX_DAYS is set correctly
    if grep -q "^PASS_MAX_DAYS" "$LOGIN_DEFS_FILE"; then
        sudo sed -i "s/^PASS_MAX_DAYS.*/PASS_MAX_DAYS $PASS_MAX_DAYS_VALUE/" "$LOGIN_DEFS_FILE"
    else
        echo "PASS_MAX_DAYS $PASS_MAX_DAYS_VALUE" | sudo tee -a "$LOGIN_DEFS_FILE"
    fi

    echo "$LOGIN_DEFS_FILE configured successfully."
}

# Function to modify maxdays for all users
set_user_pass_maxdays() {
    echo "Setting maxdays for all users with a password to $PASS_MAX_DAYS_VALUE..."

    # Get all users with a password set and update their maxdays
    for user in $(awk -F: '($2 != "*" && $2 != "!" ) {print $1}' /etc/shadow); do
        echo "Updating maxdays for user $user..."
        sudo chage --maxdays $PASS_MAX_DAYS_VALUE "$user"
    done

    echo "User maxdays settings updated successfully."
}


backup_file_login() {
    local file_path="$1"
    echo "Backing up $file_path..."
    sudo cp "$file_path" "${file_path}.bak"
    if [ $? -eq 0 ]; then
        echo "Backup of $file_path created at ${file_path}.bak"
    else
        echo "Failed to create backup of $file_path."
        exit 1
    fi
}

# Function to modify /etc/pam.d/common-password
configure_common_password() {
    echo "Configuring $COMMON_PASSWORD_FILE for pam_unix.so without hashing algorithm..."

    # Backup the file
    backup_file_login "$COMMON_PASSWORD_FILE"

    # Ensure no hashing algorithm is set for pam_unix.so
    sudo sed -i '/pam_unix.so/ s/\s\+sha512\|\s\+md5//' "$COMMON_PASSWORD_FILE"

    echo "$COMMON_PASSWORD_FILE configured successfully."
}

# Function to modify /etc/login.defs for ENCRYPT_METHOD
configure_login_defs() {
    echo "Configuring $LOGIN_DEFS_FILE to set ENCRYPT_METHOD to yescrypt..."

    # Backup the file
    backup_file_login "$LOGIN_DEFS_FILE"

    # Ensure ENCRYPT_METHOD is set to yescrypt
    if grep -q "^ENCRYPT_METHOD" "$LOGIN_DEFS_FILE"; then
        sudo sed -i 's/^ENCRYPT_METHOD.*/ENCRYPT_METHOD yescrypt/' "$LOGIN_DEFS_FILE"
    else
        echo "ENCRYPT_METHOD yescrypt" | sudo tee -a "$LOGIN_DEFS_FILE"
    fi

    echo "$LOGIN_DEFS_FILE configured successfully."
}

backup_file() {
    local file_path="$1"
    echo "Backing up $file_path..."
    sudo cp "$file_path" "${file_path}.bak"
    if [ $? -eq 0 ]; then
        echo "Backup of $file_path created at ${file_path}.bak"
    else
        echo "Failed to create backup of $file_path."
        exit 1
    fi
}

# Function to configure /etc/pam.d/common-auth
configure_common_auth() {
    echo "Configuring $COMMON_AUTH_FILE for pam_faillock..."
    
    # Backup the file
    backup_file "$COMMON_AUTH_FILE"

    # Insert the required pam_faillock lines surrounding the pam_unix.so line
    sudo sed -i '/pam_unix.so/!b;n;i auth [default=die] pam_faillock.so authfail # Added to enable faillock' "$COMMON_AUTH_FILE"
    sudo sed -i '/pam_unix.so/i auth required pam_faillock.so preauth # Added to enable faillock' "$COMMON_AUTH_FILE"
    sudo sed -i '/pam_permit.so/i auth sufficient pam_faillock.so authsucc # Added to enable faillock' "$COMMON_AUTH_FILE"

    echo "$COMMON_AUTH_FILE configured successfully."
}

# Function to configure /etc/pam.d/common-account
configure_common_account() {
    echo "Configuring $COMMON_ACCOUNT_FILE for pam_faillock..."

    # Backup the file
    backup_file "$COMMON_ACCOUNT_FILE"

    # Add the required line at the end of the file
    if ! grep -q "pam_faillock.so" "$COMMON_ACCOUNT_FILE"; then
        echo "account required pam_faillock.so" | sudo tee -a "$COMMON_ACCOUNT_FILE"
    fi

    echo "$COMMON_ACCOUNT_FILE configured successfully."
}

# Function to configure /etc/security/faillock.conf
configure_faillock_conf() {
    echo "Configuring $FAILLOCK_CONF_FILE for site policy..."

    # Backup the file
    backup_file "$FAILLOCK_CONF_FILE"

    # Write the example configuration to the file
    sudo bash -c "cat > $FAILLOCK_CONF_FILE" <<EOL
deny = 4
fail_interval = 900
unlock_time = 600
EOL

    echo "$FAILLOCK_CONF_FILE configured successfully."
}

backup_pam_file() {
    echo "Backing up $PAM_PASSWORD_FILE..."
    sudo cp "$PAM_PASSWORD_FILE" "${PAM_PASSWORD_FILE}.bak"

    if [ $? -eq 0 ]; then
        echo "Backup created at ${PAM_PASSWORD_FILE}.bak"
    else
        echo "Failed to create backup of $PAM_PASSWORD_FILE."
        exit 1
    fi
}

# Function to modify or add the remember option in /etc/pam.d/common-password
modify_pam_password_file() {
    echo "Modifying $PAM_PASSWORD_FILE to include remember option..."

    # Check if the pam_unix.so line with remember exists
    if grep -q "pam_unix.so.*remember=" "$PAM_PASSWORD_FILE"; then
        sudo sed -i 's/pam_unix.so.*/'"$PAM_PASSWORD_ENTRY"'/' "$PAM_PASSWORD_FILE"
    else
        # If the line does not exist, append the new configuration
        echo "$PAM_PASSWORD_ENTRY" | sudo tee -a "$PAM_PASSWORD_FILE"
    fi

    echo "PAM configuration updated successfully."
}
add_logfile_to_sudoers() {
    echo "Adding logfile directive to $SUDOERS_FILE..."

    # Check if the logfile directive is already present
    if sudo grep -q "^Defaults logfile=" "$SUDOERS_FILE"; then
        echo "Logfile directive already exists in $SUDOERS_FILE."
    else
        # Use visudo to safely edit the sudoers file
        echo "$SUDOERS_LOGFILE_ENTRY" | sudo EDITOR='tee -a' visudo
        if [ $? -eq 0 ]; then
            echo "Logfile directive added successfully to $SUDOERS_FILE."
        else
            echo "Failed to add logfile directive."
            exit 1
        fi
    fi
}
# Function to modify the /etc/fstab file
modify_fstab() {
    echo "Modifying $FSTAB_FILE to add noexec to the /dev/shm mount options..."
    
    # Check if /dev/shm exists in fstab
    if grep -q "$SHM_MOUNT" "$FSTAB_FILE"; then
        # Backup fstab before editing
        sudo cp "$FSTAB_FILE" "${FSTAB_FILE}.bak"
        echo "Backup of fstab created at ${FSTAB_FILE}.bak"
        
        # Modify the line for /dev/shm in /etc/fstab
        sudo sed -i "/\s\/dev\/shm\s/ s/defaults.*/$MOUNT_OPTIONS 0 0/" "$FSTAB_FILE"
        
        echo "/dev/shm entry updated in $FSTAB_FILE."
    else
        echo "/dev/shm partition not found in $FSTAB_FILE. You may need to add it manually."
        exit 1
    fi
}

modify_journald_conf() {
    echo "Modifying $JOURNALD_CONF to set Compress=yes..."
    
    # Check if Compress= exists, and modify it if necessary
    if grep -q "^Compress=" "$JOURNALD_CONF"; then
        sudo sed -i 's/^Compress=.*/Compress=yes/' "$JOURNALD_CONF"
    else
        echo "Compress=yes" | sudo tee -a "$JOURNALD_CONF"
    fi
    
    echo "$JOURNALD_CONF updated successfully."
}

# Function to restart the systemd-journald service
restart_journald_service() {
    echo "Restarting systemd-journald service..."
    sudo systemctl restart systemd-journald
    
    if [ $? -eq 0 ]; then
        echo "systemd-journald service restarted successfully."
    else
        echo "Failed to restart systemd-journald service."
        exit 1
    fi
}
modify_journald_conf2() {
    echo "Modifying $JOURNALD_CONF to set Storage=persistent..."
    
    # Check if Storage= exists, and modify it if necessary
    if grep -q "^Storage=" "$JOURNALD_CONF"; then
        sudo sed -i 's/^Storage=.*/Storage=persistent/' "$JOURNALD_CONF"
    else
        echo "Storage=persistent" | sudo tee -a "$JOURNALD_CONF"
    fi
    
    echo "$JOURNALD_CONF updated successfully."
}
restart_journald_service2() {
    echo "Restarting systemd-journald service..."
    sudo systemctl restart systemd-journald
    
    if [ $? -eq 0 ]; then
        echo "systemd-journald service restarted successfully."
    else
        echo "Failed to restart systemd-journald service."
        exit 1
    fi
}

create_scope_rules() {
    echo "Creating or appending to $SCOPE_RULES_FILE with the relevant rules..."
    
    # Append the rules for monitoring changes in /etc/sudoers and /etc/sudoers.d
    printf " -w /etc/sudoers -p wa -k scope\n -w /etc/sudoers.d -p wa -k scope\n" | sudo tee -a "$SCOPE_RULES_FILE"
    
    echo "Audit rules for monitoring scope changes added successfully."
}
create_user_emulation_rules() {
    echo "Creating or appending to $USER_EMULATION_RULES_FILE with the relevant rules..."
    
    # Append the rules for 64-bit and 32-bit systems
    printf " -a always,exit -F arch=b64 -C euid!=uid -F auid!=unset -S execve -k user_emulation\n" | sudo tee -a "$USER_EMULATION_RULES_FILE"
    printf " -a always,exit -F arch=b32 -C euid!=uid -F auid!=unset -S execve -k user_emulation\n" | sudo tee -a "$USER_EMULATION_RULES_FILE"
    
    echo "Audit rules for elevated privileges added successfully."
}
create_time_change_rules() {
    echo "Creating or appending to $TIME_CHANGE_RULES_FILE with the relevant rules..."
    
    # Append the rules for 64-bit systems
    printf " -a always,exit -F arch=b64 -S adjtimex,settimeofday,clock_settime -k time-change\n" | sudo tee -a "$TIME_CHANGE_RULES_FILE"
    
    # Append the rules for 32-bit systems, including stime for 32-bit only
    printf " -a always,exit -F arch=b32 -S adjtimex,settimeofday,clock_settime,stime -k time-change\n" | sudo tee -a "$TIME_CHANGE_RULES_FILE"
    
    # Add rule to monitor /etc/localtime for changes
    printf " -w /etc/localtime -p wa -k time-change\n" | sudo tee -a "$TIME_CHANGE_RULES_FILE"
    
    echo "Audit rules for monitoring time changes added successfully."
}
create_network_env_rules() {
    echo "Creating or appending to $NETWORK_ENV_RULES_FILE with the relevant rules..."
    
    # Append the rules for 64-bit systems
    printf " -a always,exit -F arch=b64 -S sethostname,setdomainname -k system-locale\n" | sudo tee -a "$NETWORK_ENV_RULES_FILE"
    
    # Append the rules for 32-bit systems
    printf " -a always,exit -F arch=b32 -S sethostname,setdomainname -k system-locale\n" | sudo tee -a "$NETWORK_ENV_RULES_FILE"
    
    # Add rules to monitor system files related to network configuration
    printf " -w /etc/issue -p wa -k system-locale\n" | sudo tee -a "$NETWORK_ENV_RULES_FILE"
    printf " -w /etc/issue.net -p wa -k system-locale\n" | sudo tee -a "$NETWORK_ENV_RULES_FILE"
    printf " -w /etc/hosts -p wa -k system-locale\n" | sudo tee -a "$NETWORK_ENV_RULES_FILE"
    printf " -w /etc/networks -p wa -k system-locale\n" | sudo tee -a "$NETWORK_ENV_RULES_FILE"
    printf " -w /etc/network/ -p wa -k system-locale\n" | sudo tee -a "$NETWORK_ENV_RULES_FILE"
    
    echo "Audit rules for monitoring network environment changes added successfully."
}
create_login_rules() {
    echo "Creating or appending to $LOGIN_RULES_FILE with the relevant rules..."
    
    # Append the rules to monitor login/logout event files
    printf "  -w /var/log/lastlog -p wa -k logins\n" | sudo tee -a "$LOGIN_RULES_FILE"
    printf "  -w /var/run/faillock -p wa -k logins\n" | sudo tee -a "$LOGIN_RULES_FILE"
    
    echo "Audit rules for monitoring login and logout events added successfully."
}
create_identity_rules() {
    echo "Creating or appending to $IDENTITY_RULES_FILE with the relevant rules..."
    
    # Append the rules to monitor changes in user/group information files
    printf " -w /etc/group -p wa -k identity\n" | sudo tee -a "$IDENTITY_RULES_FILE"
    printf " -w /etc/passwd -p wa -k identity\n" | sudo tee -a "$IDENTITY_RULES_FILE"
    printf " -w /etc/gshadow -p wa -k identity\n" | sudo tee -a "$IDENTITY_RULES_FILE"
    printf " -w /etc/shadow -p wa -k identity\n" | sudo tee -a "$IDENTITY_RULES_FILE"
    printf " -w /etc/security/opasswd -p wa -k identity\n" | sudo tee -a "$IDENTITY_RULES_FILE"
    
    echo "Audit rules for monitoring user/group information changes added successfully."
}
create_session_rules() {
    echo "Creating or appending to $SESSION_RULES_FILE with the relevant rules..."
    
    # Append the rules to monitor session initiation files
    printf " -w /var/run/utmp -p wa -k session\n" | sudo tee -a "$SESSION_RULES_FILE"
    printf " -w /var/log/wtmp -p wa -k session\n" | sudo tee -a "$SESSION_RULES_FILE"
    printf " -w /var/log/btmp -p wa -k session\n" | sudo tee -a "$SESSION_RULES_FILE"
    
    echo "Audit rules for monitoring session initiation information added successfully."
}
create_mac_policy_rules() {
    echo "Creating or appending to $MAC_POLICY_RULES_FILE with the relevant rules..."
    
    # Append the rules to monitor MAC policy directories
    printf " -w /etc/apparmor/ -p wa -k MAC-policy\n" | sudo tee -a "$MAC_POLICY_RULES_FILE"
    printf " -w /etc/apparmor.d/ -p wa -k MAC-policy\n" | sudo tee -a "$MAC_POLICY_RULES_FILE"
    
    echo "Audit rules for monitoring MAC policy changes added successfully."
}
create_finalize_rule() {
    echo "Creating or appending the final audit rule to $FINALIZE_RULES_FILE..."
    
    # Append the -e 2 rule to lock the audit configuration
    printf " -e 2\n" | sudo tee -a "$FINALIZE_RULES_FILE"
    
    echo "Final audit rule added successfully."
}

#!/bin/bash

# Function to remove /etc/cron.deny
remove_cron_deny() {
    if [ -f /etc/cron.deny ]; then
        echo "Removing /etc/cron.deny..."
        sudo rm /etc/cron.deny

        if [ $? -eq 0 ]; then
            echo "/etc/cron.deny removed successfully."
        else
            echo "Failed to remove /etc/cron.deny."
            exit 1
        fi
    else
        echo "/etc/cron.deny does not exist, skipping removal."
    fi
}

# Function to create /etc/cron.allow
create_cron_allow() {
    echo "Creating /etc/cron.allow..."
    sudo touch /etc/cron.allow

    if [ $? -eq 0 ]; then
        echo "/etc/cron.allow created successfully."
    else
        echo "Failed to create /etc/cron.allow."
        exit 1
    fi
}

# Function to set permissions and ownership for /etc/cron.allow
set_cron_allow_permissions() {
    echo "Setting permissions and ownership for /etc/cron.allow..."
    
    # Set the correct permissions
    sudo chmod g-wx,o-rwx /etc/cron.allow
    if [ $? -eq 0 ]; then
        echo "Permissions set successfully."
    else
        echo "Failed to set permissions."
        exit 1
    fi

    # Set the correct ownership
    sudo chown root:root /etc/cron.allow
    if [ $? -eq 0 ]; then
        echo "Ownership set successfully."
    else
        echo "Failed to set ownership."
        exit 1
    fi
}

# Main script execution
add_logfile_to_sudoers
create_scope_rules
create_mac_policy_rules
create_user_emulation_rules
create_time_change_rules
create_network_env_rules
create_identity_rules
create_session_rules
create_login_rules
create_finalize_rule
modify_grub_config
update_grub_config
modify_journald_conf
restart_journald_service
modify_journald_conf2
restart_journald_service2
backup_pam_file
modify_pam_password_file
remove_cron_deny
create_cron_allow
set_cron_allow_permissions
# configure_common_auth
# configure_common_account
configure_faillock_conf
set_pass_max_days
set_user_pass_maxdays
set_grub_permissions
# configure_common_password
# configure_login_defs

echo "ForwardToSyslog=yes" >>  /etc/systemd/journald.conf
echo "$FileCreateMode 0640" >> /etc/rsyslog.conf
echo "Authorized uses only. All activity may be monitored and reported." > /etc/issue
echo "Authorized uses only. All activity may be monitored and reported." > /etc/issue.net

chown root /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/autrace /sbin/auditd /sbin/augenrules
chown root:root /etc/crontab
chmod og-rwx /etc/crontab
chown root:root /etc/cron.hourly/
chmod og-rwx /etc/cron.hourly/
chown root:root /etc/cron.daily/
chmod og-rwx /etc/cron.daily/
chown root:root /etc/cron.monthly/
chmod og-rwx /etc/cron.monthly/
chown root:root /etc/cron.d/
chmod og-rwx /etc/cron.d/
chown root:root /etc/ssh/sshd_config
chmod og-rwx /etc/ssh/sshd_config
chown root:root /etc/cron.weekly/
chmod og-rwx /etc/cron.weekly/
echo "Remediation completed successfully."
#Setup timezone
systemctl enable rsyslog.service
systemctl enable systemd-journald.service
timedatectl set-timezone Asia/Ho_Chi_Minh
systemctl restart auditd.service
systemctl restart rsyslog.service
systemctl restart sshd

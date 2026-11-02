control 'SV-277154' do
  title 'The macOS system must enforce multifactor authentication for privilege escalation through the sudo command.'
  desc 'The system must be configured to enforce multifactor authentication when the sudo command is used to elevate privilege.

All users must go through multifactor authentication to prevent unauthenticated access and potential compromise to the system.

IMPORTANT: Modification of Pluggable Authentication Modules (PAM) now requires user authorization, or use of a Privacy Preferences Policy Control (PPPC) profile from MDM that authorizes modifying system administrator files or full disk access.

Note: /etc/pam.d/sudo will be automatically modified to its original state following any update or major upgrade to the operating system.

'
  desc 'check', %q(Verify the macOS system is configured to enforce multifactor authentication for privilege escalation through the sudo command with the following command:

/usr/bin/grep -Ec '^(auth\s+sufficient\s+pam_smartcard.so|auth\s+required\s+pam_deny.so)' /etc/pam.d/sudo

If the result is not "2", this is a finding.)
  desc 'fix', 'Configure the macOS system to enforce multifactor authentication for privilege escalation through the sudo command with the following commands:

/bin/cat > /etc/pam.d/sudo << SUDO_END
# sudo: auth account password session
auth        sufficient    pam_smartcard.so
auth        required      pam_opendirectory.so
auth        required      pam_deny.so
account     required      pam_permit.so
password    required      pam_deny.so
session     required      pam_permit.so
SUDO_END

/bin/chmod 444 /etc/pam.d/sudo
/usr/sbin/chown root:wheel /etc/pam.d/sudo'
  impact 0.5
  tag check_id: 'C-81309r1148912_chk'
  tag severity: 'medium'
  tag gid: 'V-277154'
  tag rid: 'SV-277154r1268228_rule'
  tag stig_id: 'APPL-26-003052'
  tag gtitle: 'SRG-OS-000105-GPOS-00052'
  tag fix_id: 'F-81214r1148913_fix'
  tag satisfies: ['SRG-OS-000105-GPOS-00052', 'SRG-OS-000106-GPOS-00053', 'SRG-OS-000107-GPOS-00054', 'SRG-OS-000108-GPOS-00055', 'SRG-OS-000112-GPOS-00057', 'SRG-OS-000705-GPOS-00150']
  tag 'documentable'
  tag cci: ['CCI-000765', 'CCI-000766', 'CCI-001941', 'CCI-004047']
  tag nist: ['IA-2 (1)', 'IA-2 (2)', 'IA-2 (8)', 'IA-2 (6) (b)']
end

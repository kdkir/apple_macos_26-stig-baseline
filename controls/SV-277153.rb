control 'SV-277153' do
  title 'The macOS system must enforce multifactor authentication for the su command.'
  desc 'The system must be configured such that, when the su command is used, multifactor authentication is enforced.

All users must go through multifactor authentication to prevent unauthenticated access and potential compromise to the system.

IMPORTANT: Modification of Pluggable Authentication Modules (PAM) now requires user authorization or use of a Privacy Preferences Policy Control (PPPC) profile from MDM that authorizes modifying system administrator files or full disk access.

Note: /etc/pam.d/su will be automatically modified to its original state following any update or major upgrade to the operating system.

'
  desc 'check', %q(Verify the macOS system is configured to enforce multifactor authentication for the su command with the following command:

/usr/bin/grep -Ec '^(auth\s+sufficient\s+pam_smartcard.so|auth\s+required\s+pam_rootok.so)' /etc/pam.d/su

If the result is not "2", this is a finding.)
  desc 'fix', 'Configure the macOS system to enforce multifactor authentication for the su command with the following commands:

/bin/cat > /etc/pam.d/su << SU_END
# su: auth account password session
auth        sufficient    pam_smartcard.so
auth        required      pam_rootok.so
auth        required      pam_group.so no_warn group=admin,wheel ruser root_only fail_safe
account     required      pam_permit.so
account     required      pam_opendirectory.so no_check_shell
password    required      pam_opendirectory.so
session     required      pam_launchd.so
SU_END

# Fix new file ownership and permissions
/bin/chmod 644 /etc/pam.d/su
/usr/sbin/chown root:wheel /etc/pam.d/su'
  impact 0.5
  tag check_id: 'C-81308r1148909_chk'
  tag severity: 'medium'
  tag gid: 'V-277153'
  tag rid: 'SV-277153r1268228_rule'
  tag stig_id: 'APPL-26-003051'
  tag gtitle: 'SRG-OS-000105-GPOS-00052'
  tag fix_id: 'F-81213r1148910_fix'
  tag satisfies: ['SRG-OS-000105-GPOS-00052', 'SRG-OS-000106-GPOS-00053', 'SRG-OS-000107-GPOS-00054', 'SRG-OS-000108-GPOS-00055', 'SRG-OS-000112-GPOS-00057', 'SRG-OS-000705-GPOS-00150']
  tag 'documentable'
  tag cci: ['CCI-000765', 'CCI-000766', 'CCI-001941', 'CCI-004047']
  tag nist: ['IA-2 (1)', 'IA-2 (2)', 'IA-2 (8)', 'IA-2 (6) (b)']

  describe file('/etc/pam.d/su') do
    its('content') { should match(/^auth\s+sufficient\s+pam_smartcard\.so/) }
    its('content') { should match(/^auth\s+required\s+pam_rootok\.so/) }
  end
end

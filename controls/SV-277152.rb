control 'SV-277152' do
  title 'The macOS system must enforce multifactor authentication for login.'
  desc 'The system must be configured to enforce multifactor authentication.

All users must go through multifactor authentication to prevent unauthenticated access and potential compromise to the system.

IMPORTANT: Modification of Pluggable Authentication Modules (PAM) now requires user authorization or use of a Privacy Preferences Policy Control (PPPC) profile from MDM that authorizes modifying system administrator files or full disk access.

Note: /etc/pam.d/login will be automatically modified to its original state following any update or major upgrade to the operating system.

'
  desc 'check', %q(Verify the macOS system is configured to enforce multifactor authentication for login with the following command:

/usr/bin/grep -Ec '^(auth\s+sufficient\s+pam_smartcard.so|auth\s+required\s+pam_deny.so)' /etc/pam.d/login

If the result is not "2", this is a finding.)
  desc 'fix', 'Configure the macOS system to enforce multifactor authentication for login with the following commands:

/bin/cat > /etc/pam.d/login << LOGIN_END
# login: auth account password session
auth        sufficient    pam_smartcard.so
auth        optional      pam_krb5.so use_kcminit
auth        optional      pam_ntlm.so try_first_pass
auth        optional      pam_mount.so try_first_pass
auth        required      pam_opendirectory.so try_first_pass
auth        required      pam_deny.so
account     required      pam_nologin.so
account     required      pam_opendirectory.so
password    required      pam_opendirectory.so
session     required      pam_launchd.so
session     required      pam_uwtmp.so
session     optional      pam_mount.so
LOGIN_END

/bin/chmod 644 /etc/pam.d/login
/usr/sbin/chown root:wheel /etc/pam.d/login'
  impact 0.5
  tag check_id: 'C-81307r1148906_chk'
  tag severity: 'medium'
  tag gid: 'V-277152'
  tag rid: 'SV-277152r1268228_rule'
  tag stig_id: 'APPL-26-003050'
  tag gtitle: 'SRG-OS-000105-GPOS-00052'
  tag fix_id: 'F-81212r1148907_fix'
  tag satisfies: ['SRG-OS-000105-GPOS-00052', 'SRG-OS-000106-GPOS-00053', 'SRG-OS-000107-GPOS-00054', 'SRG-OS-000108-GPOS-00055', 'SRG-OS-000112-GPOS-00057', 'SRG-OS-000705-GPOS-00150']
  tag 'documentable'
  tag cci: ['CCI-000765', 'CCI-000766', 'CCI-001941', 'CCI-004047']
  tag nist: ['IA-2 (1)', 'IA-2 (2)', 'IA-2 (8)', 'IA-2 (6) (b)']
end

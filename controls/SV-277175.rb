control 'SV-277175' do
  title 'The macOS system must enable Authenticated Root.'
  desc 'Authenticated Root must be enabled.

When Authenticated Root is enabled, the macOS is booted from a signed volume that is cryptographically protected to prevent tampering with the system volume.

Note: Authenticated Root is enabled by default on macOS systems.

WARNING: If more than one partition with macOS is detected, the csrutil command will hang awaiting input.'
  desc 'check', 'Verify the macOS system is configured to enable authenticated root with the following command:

/usr/libexec/mdmclient QuerySecurityInfo 2>/dev/null | /usr/bin/grep -c "AuthenticatedRootVolumeEnabled = 1;"

If the result is not "1", this is a finding.'
  desc 'fix', 'Configure the macOS system to enable authenticated root with the following command:

/usr/bin/csrutil authenticated-root enable

Note: To reenable "Authenticated Root", boot the affected system into "Recovery" mode, launch "Terminal" from the "Utilities" menu, and run the command.'
  impact 0.5
  tag check_id: 'C-81330r1149333_chk'
  tag severity: 'medium'
  tag gid: 'V-277175'
  tag rid: 'SV-277175r1268226_rule'
  tag stig_id: 'APPL-26-005070'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-81235r1148976_fix'
  tag 'documentable'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end

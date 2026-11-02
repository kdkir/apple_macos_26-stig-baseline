control 'SV-277180' do
  title 'The macOS system must enable Recovery Lock.'
  desc 'A Recovery Lock password must be enabled and set.

Single user mode, recovery mode, the Startup Manager, and several other tools are available on macOS by holding down specific key combinations during startup. Setting a recovery lock restricts access to these tools.

IMPORTANT: Recovery lock passwords are not supported on Intel devices. This rule is only applicable to Apple Silicon devices.'
  desc 'check', 'For non-Apple Silicon systems, this is not applicable.

Verify the macOS system is configured with Recovery Lock with the following command:

/usr/libexec/mdmclient QuerySecurityInfo 2>/dev/null | /usr/bin/grep -c "IsRecoveryLockEnabled = 1"

If the result is not "1", this is a finding.'
  desc 'fix', 'Configure the macOS system with Recovery Lock with the SetRecoveryLock command. This can be used to set a Recovery Lock password and must be from the MDM.'
  impact 0.5
  tag check_id: 'C-81335r1149337_chk'
  tag severity: 'medium'
  tag gid: 'V-277180'
  tag rid: 'SV-277180r1268251_rule'
  tag stig_id: 'APPL-26-005120'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-81240r1148991_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

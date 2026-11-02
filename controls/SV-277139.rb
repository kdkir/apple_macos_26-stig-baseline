control 'SV-277139' do
  title 'The macOS system must disable Remote Management.'
  desc 'Remote Management must be disabled.'
  desc 'check', 'Verify the macOS system is configured to disable Remote Management with the following command:

/usr/libexec/mdmclient QuerySecurityInfo 2>/dev/null | /usr/bin/grep -c "RemoteDesktopEnabled = 0"

If the result is not "1", this is a finding.'
  desc 'fix', 'Configure the macOS system to disable Remote Management with the following commands:

/System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart -deactivate -stop'
  impact 0.5
  tag check_id: 'C-81294r1149352_chk'
  tag severity: 'medium'
  tag gid: 'V-277139'
  tag rid: 'SV-277139r1149403_rule'
  tag stig_id: 'APPL-26-002250'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-81199r1148868_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end

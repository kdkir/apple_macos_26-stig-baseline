control 'SV-277102' do
  title 'The macOS system must disable Remote Apple Events.'
  desc 'If the system does not require Remote Apple Events, support for Apple Remote Events is nonessential and must be disabled.

The information system must be configured to provide only essential capabilities. Disabling Remote Apple Events helps prevent unauthorized connection of devices, transfer of information, and tunneling.

'
  desc 'check', %q(Verify the macOS system is configured to disable Remote Apple Events with the following command:

/bin/launchctl print-disabled system | /usr/bin/grep -c '"com.apple.AEServer" => disabled'

If the result is not "1", this is a finding.)
  desc 'fix', 'Configure the macOS system to disable Remote Apple Events with the following commands:

/usr/sbin/systemsetup -setremoteappleevents off
/bin/launchctl disable system/com.apple.AEServer

Note: Systemsetup with -setremoteappleevents flag will fail unless Full Disk Access to systemsetup or its parent process is granted. This requires supervision.'
  impact 0.5
  tag check_id: 'C-81257r1148756_chk'
  tag severity: 'medium'
  tag gid: 'V-277102'
  tag rid: 'SV-277102r1268226_rule'
  tag stig_id: 'APPL-26-002022'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-81162r1148757_fix'
  tag satisfies: ['SRG-OS-000080-GPOS-00048', 'SRG-OS-000096-GPOS-00050']
  tag 'documentable'
  tag cci: ['CCI-000213', 'CCI-000382']
  tag nist: ['AC-3', 'CM-7 b']
end

control 'SV-277140' do
  title 'The macOS system must disable the Bluetooth System Settings pane.'
  desc 'The Bluetooth System Setting pane must be disabled to prevent access to the Bluetooth configuration.'
  desc 'check', %q(Verify the macOS system is configured to disable the Bluetooth System Settings pane with the following command:

/usr/bin/profiles show -output stdout-xml | /usr/bin/xmllint --xpath '//key[text()="DisabledSystemSettings"]/following-sibling::*[1]' - | /usr/bin/grep -c com.apple.BluetoothSettings

If the result is not "1", this is a finding.)
  desc 'fix', 'Configure the macOS system to disable the Bluetooth System Settings pane by installing the "com.apple.systempreferences" configuration profiles.'
  impact 0.5
  tag check_id: 'C-81295r1148870_chk'
  tag severity: 'medium'
  tag gid: 'V-277140'
  tag rid: 'SV-277140r1148872_rule'
  tag stig_id: 'APPL-26-002260'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-81200r1148871_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end

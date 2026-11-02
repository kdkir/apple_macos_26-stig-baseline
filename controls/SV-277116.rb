control 'SV-277116' do
  title 'The macOS system must disable the system settings pane for Siri.'
  desc 'The System Settings pane for Siri must be hidden.

Hiding the System Settings pane prevents users from configuring Siri. Enabling any service increases the attack surface for an intruder. By disabling unnecessary services, the attack surface is minimized.'
  desc 'check', %q(Verify the macOS system is configured to disable the system settings pane for Siri with the following command:

/usr/bin/profiles show -output stdout-xml | /usr/bin/xmllint --xpath '//key[text()="DisabledSystemSettings"]/following-sibling::*[1]' - | /usr/bin/grep -c com.apple.Siri-Settings.extension

If the result is not "1", this is a finding.)
  desc 'fix', 'Configure the macOS system to disable the system settings pane for Siri by installing the "com.apple.systempreferences" configuration profile.'
  impact 0.5
  tag check_id: 'C-81271r1148798_chk'
  tag severity: 'medium'
  tag gid: 'V-277116'
  tag rid: 'SV-277116r1148800_rule'
  tag stig_id: 'APPL-26-002053'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-81176r1148799_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end

control 'SV-277087' do
  title 'The macOS system must disable Location Services.'
  desc 'Location Services must be disabled.

The information system must be configured to provide only essential capabilities. Disabling Location Services helps prevent unauthorized connection of devices, transfer of information, and tunneling.'
  desc 'check', %q(Verify the macOS system is configured to disable Location Services with the following command:

/usr/bin/sudo -u _locationd /usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.locationd')\
.objectForKey('LocationServicesEnabled').js
EOS

If the result is not "false", this is a finding.)
  desc 'fix', "Configure the macOS system to disable Location Services with the following command:

  /usr/bin/defaults write /var/db/locationd/Library/Preferences/ByHost/com.apple.locationd LocationServicesEnabled -bool false; 
  pid=$(/bin/launchctl print system | /usr/bin/awk '/\\tcom.apple.locationd/ {print $1}')
  kill -9 $pid"
  impact 0.5
  tag check_id: 'C-81242r1148711_chk'
  tag severity: 'medium'
  tag gid: 'V-277087'
  tag rid: 'SV-277087r1149413_rule'
  tag stig_id: 'APPL-26-002004'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-81147r1149372_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']

  describe macos_managed_preference('com.apple.locationd', 'LocationServicesEnabled', user: '_locationd') do
    its('value') { should eq false }
  end
end

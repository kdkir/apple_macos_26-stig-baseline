control 'SV-277033' do
  title 'The macOS system must prevent AdminHostInfo from being available at LoginWindow.'
  desc 'The system must be configured to not display sensitive information at the LoginWindow. If the key "AdminHostInfo" is configured with a string value, it will allow the HostName, IP Address, and operating system version and build to be displayed when clicking on the clock area of the login window. Configuring this key to be an integer value, since it expects a string value, will effectively disable the behavior.

Note: This configuration requires it to be deployed via Managed Preferences rather than directly to com.apple.loginwindow.'
  desc 'check', %q(Verify the macOS system is configured to prevent AdminHostInfo from being available at LoginWindow with the following command:

/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.loginwindow')\
.integerForKey('AdminHostInfo')
EOS

If the result is not "-1", this is a finding.)
  desc 'fix', 'Configure the macOS system to prevent AdminHostInfo from being available at LoginWindow by installing the "com.apple.ManagedClient.preferences" configuration profile.'
  impact 0.5
  tag check_id: 'C-81188r1149339_chk'
  tag severity: 'medium'
  tag gid: 'V-277033'
  tag rid: 'SV-277033r1149397_rule'
  tag stig_id: 'APPL-26-000009'
  tag gtitle: 'SRG-OS-000031-GPOS-00012'
  tag fix_id: 'F-81093r1149340_fix'
  tag 'documentable'
  tag cci: ['CCI-000060']
  tag nist: ['AC-11 (1)']
end

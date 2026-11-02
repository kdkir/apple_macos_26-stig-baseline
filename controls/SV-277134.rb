control 'SV-277134' do
  title 'The macOS system must disable Personalized Advertising.'
  desc "Ad tracking and targeted ads must be disabled.

The information system must be configured to provide only essential capabilities. Disabling ad tracking ensures that applications and advertisers are unable to track users' interests and deliver targeted advertisements."
  desc 'check', %q(Verify the macOS system is configured to disable Personalized Advertising with the following command:

/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess')\
.objectForKey('allowApplePersonalizedAdvertising').js
EOS

If the result is not "false", this is a finding.)
  desc 'fix', 'Configure the macOS system to disable Personalized Advertising by installing the "com.apple.applicationaccess" configuration profile.'
  impact 0.5
  tag check_id: 'C-81289r1148852_chk'
  tag severity: 'medium'
  tag gid: 'V-277134'
  tag rid: 'SV-277134r1148854_rule'
  tag stig_id: 'APPL-26-002200'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-81194r1148853_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end

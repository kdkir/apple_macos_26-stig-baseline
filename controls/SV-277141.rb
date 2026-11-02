control 'SV-277141' do
  title 'The macOS system must disable the iCloud Freeform services.'
  desc "The macOS built-in Freeform.app connection to Apple's iCloud service must be disabled.

Enabling any service increases the attack surface for an intruder. By disabling unnecessary services, the attack surface is minimized."
  desc 'check', %q(Verify the macOS system is configured to disable iCloud Freeform services with the following command:

/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess')\
.objectForKey('allowCloudFreeform').js
EOS

If the result is not "false", this is a finding.)
  desc 'fix', 'Configure the macOS system to disable iCloud Freeform services by installing the "com.apple.applicationaccess" configuration profile.'
  impact 0.5
  tag check_id: 'C-81296r1148873_chk'
  tag severity: 'medium'
  tag gid: 'V-277141'
  tag rid: 'SV-277141r1148875_rule'
  tag stig_id: 'APPL-26-002270'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-81201r1148874_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']

  describe macos_managed_preference('com.apple.applicationaccess', 'allowCloudFreeform') do
    its('value') { should eq false }
  end
end

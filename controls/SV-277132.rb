control 'SV-277132' do
  title 'The macOS system must disable iCloud Private Relay.'
  desc 'Enterprise networks may be required to audit all network traffic by policy; therefore, iCloud Private Relay must be disabled.

Network administrators can also prevent the use of this feature by blocking DNS resolution of mask.icloud.com and mask-h2.icloud.com.'
  desc 'check', %q(Verify the macOS system is configured to disable the iCloud Private Relay with the following command:

/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess')\
.objectForKey('allowCloudPrivateRelay').js
EOS

If the result is not "false", this is a finding.)
  desc 'fix', 'Configure the macOS system to disable the iCloud Private Relay by installing the "com.apple.applicationaccess" configuration profile.'
  impact 0.5
  tag check_id: 'C-81287r1148846_chk'
  tag severity: 'medium'
  tag gid: 'V-277132'
  tag rid: 'SV-277132r1148848_rule'
  tag stig_id: 'APPL-26-002170'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-81192r1148847_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']

  describe macos_managed_preference('com.apple.applicationaccess', 'allowCloudPrivateRelay') do
    its('value') { should eq false }
  end
end

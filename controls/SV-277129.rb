control 'SV-277129' do
  title 'The macOS system must disable Content Caching service.'
  desc 'Content Caching must be disabled.

Content Caching is a macOS service that helps reduce internet data usage and speed up software installation on Mac computers. It is not recommended for devices furnished to employees to act as a caching server.'
  desc 'check', %q(Verify the macOS system is configured to disable Content Caching service with the following command:

/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess')\
.objectForKey('allowContentCaching').js
EOS

If the result is not "false", this is a finding.)
  desc 'fix', 'Configure the macOS system to disable Content Caching service by installing the "com.apple.applicationaccess" configuration profile.'
  impact 0.5
  tag check_id: 'C-81284r1148837_chk'
  tag severity: 'medium'
  tag gid: 'V-277129'
  tag rid: 'SV-277129r1148839_rule'
  tag stig_id: 'APPL-26-002140'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-81189r1148838_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']

  describe macos_managed_preference('com.apple.applicationaccess', 'allowContentCaching') do
    its('value') { should eq false }
  end
end

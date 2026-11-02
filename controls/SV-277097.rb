control 'SV-277097' do
  title 'The macOS system must disable iCloud Mail.'
  desc "The macOS built-in Mail.app connection to Apple's iCloud service must be disabled.

Apple's iCloud service does not provide an organization with enough control over the storage and access of data and, therefore, automated mail synchronization must be controlled by an organization-approved service."
  desc 'check', %q(Verify the macOS system is configured to disable iCloud Mail with the following command:

/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess')\
.objectForKey('allowCloudMail').js
EOS

If the result is not "false", this is a finding.)
  desc 'fix', 'Configure the macOS system to disable iCloud Mail by installing the "com.apple.applicationaccess" configuration profile.'
  impact 0.5
  tag check_id: 'C-81252r1148741_chk'
  tag severity: 'medium'
  tag gid: 'V-277097'
  tag rid: 'SV-277097r1148743_rule'
  tag stig_id: 'APPL-26-002015'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-81157r1148742_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']

  describe macos_managed_preference('com.apple.applicationaccess', 'allowCloudMail') do
    its('value') { should eq false }
  end
end

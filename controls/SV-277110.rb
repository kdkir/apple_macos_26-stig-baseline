control 'SV-277110' do
  title 'The macOS system must disable iCloud Keychain Sync.'
  desc "The macOS system's ability to automatically synchronize a user's passwords to their iCloud account must be disabled.

Apple's iCloud service does not provide an organization with enough control over the storage and access of data and, therefore, password management and synchronization must be controlled by an organization-approved service."
  desc 'check', %q(Verify the macOS system is configured to disable iCloud Keychain Sync with the following command:

/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess')\
.objectForKey('allowCloudKeychainSync').js
EOS

If the result is not "false", this is a finding.)
  desc 'fix', 'Configure the macOS system to disable iCloud Keychain Sync by installing the "com.apple.applicationaccess" configuration profile.'
  impact 0.5
  tag check_id: 'C-81265r1148780_chk'
  tag severity: 'medium'
  tag gid: 'V-277110'
  tag rid: 'SV-277110r1148782_rule'
  tag stig_id: 'APPL-26-002040'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-81170r1148781_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']

  describe macos_managed_preference('com.apple.applicationaccess', 'allowCloudKeychainSync') do
    its('value') { should eq false }
  end
end

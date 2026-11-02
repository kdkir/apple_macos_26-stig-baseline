control 'SV-277096' do
  title 'The macOS system must disable iCloud Address Book.'
  desc "The macOS built-in Contacts.app connection to Apple's iCloud service must be disabled.

Apple's iCloud service does not provide an organization with enough control over the storage and access of data, and, therefore, automated contact synchronization must be controlled by an organization-approved service."
  desc 'check', %q(Verify the macOS system is configured to disable iCloud Address Book with the following command:

/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess')\
.objectForKey('allowCloudAddressBook').js
EOS

If the result is not "false", this is a finding.)
  desc 'fix', 'Configure the macOS system to disable iCloud Address Book by installing the "com.apple.applicationaccess" configuration profile.'
  impact 0.5
  tag check_id: 'C-81251r1148738_chk'
  tag severity: 'medium'
  tag gid: 'V-277096'
  tag rid: 'SV-277096r1148740_rule'
  tag stig_id: 'APPL-26-002014'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-81156r1148739_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']

  describe macos_managed_preference('com.apple.applicationaccess', 'allowCloudAddressBook') do
    its('value') { should eq false }
  end
end

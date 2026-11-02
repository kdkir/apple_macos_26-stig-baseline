control 'SV-277095' do
  title 'The macOS system must disable iCloud Reminders.'
  desc "The macOS built-in Reminders.app connection to Apple's iCloud service must be disabled.

Apple's iCloud service does not provide an organization with enough control over the storage and access of data and, therefore, automated reminders synchronization must be controlled by an organization-approved service."
  desc 'check', %q(Verify the macOS system is configured to disable iCloud Reminders with the following command:

/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess')\
.objectForKey('allowCloudReminders').js
EOS

If the result is not "false", this is a finding.)
  desc 'fix', 'Configure the macOS system to disable iCloud Reminders by installing the "com.apple.applicationaccess" configuration profile.'
  impact 0.5
  tag check_id: 'C-81250r1148735_chk'
  tag severity: 'medium'
  tag gid: 'V-277095'
  tag rid: 'SV-277095r1148737_rule'
  tag stig_id: 'APPL-26-002013'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-81155r1148736_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']

  describe macos_managed_preference('com.apple.applicationaccess', 'allowCloudReminders') do
    its('value') { should eq false }
  end
end

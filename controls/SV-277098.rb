control 'SV-277098' do
  title 'The macOS system must disable iCloud Notes.'
  desc "The macOS built-in Notes.app connection to Apple's iCloud service must be disabled.

Apple's iCloud service does not provide an organization with enough control over the storage and access of data and, therefore, automated Notes synchronization must be controlled by an organization-approved service."
  desc 'check', %q(Verify the macOS system is configured to disable iCloud Notes with the following command:

/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess')\
.objectForKey('allowCloudNotes').js
EOS

If the result is not "false", this is a finding.)
  desc 'fix', 'Configure the macOS system to disable iCloud Notes by installing the "com.apple.applicationaccess" configuration profile.'
  impact 0.5
  tag check_id: 'C-81253r1148744_chk'
  tag severity: 'medium'
  tag gid: 'V-277098'
  tag rid: 'SV-277098r1148746_rule'
  tag stig_id: 'APPL-26-002016'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-81158r1148745_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']

  describe macos_managed_preference('com.apple.applicationaccess', 'allowCloudNotes') do
    its('value') { should eq false }
  end
end

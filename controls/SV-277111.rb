control 'SV-277111' do
  title 'The macOS system must disable iCloud Document Sync.'
  desc "The macOS built-in iCloud document synchronization service must be disabled to prevent organizational data from being synchronized to personal or nonapproved storage.

Apple's iCloud service does not provide an organization with enough control over the storage and access of data and, therefore, automated document synchronization must be controlled by an organization-approved service."
  desc 'check', %q(Verify the macOS system is configured to disable iCloud Document Sync with the following command:

/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess')\
.objectForKey('allowCloudDocumentSync').js
EOS

If the result is not "false", this is a finding.)
  desc 'fix', 'Configure the macOS system to disable iCloud Document Sync by installing the "com.apple.applicationaccess" configuration profile.'
  impact 0.5
  tag check_id: 'C-81266r1148783_chk'
  tag severity: 'medium'
  tag gid: 'V-277111'
  tag rid: 'SV-277111r1148785_rule'
  tag stig_id: 'APPL-26-002041'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-81171r1148784_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end

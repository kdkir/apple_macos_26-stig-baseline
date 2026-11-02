control 'SV-277130' do
  title 'The macOS system must disable iCloud Desktop and Document folder sync.'
  desc "The macOS system's ability to automatically synchronize a user's Desktop and Documents folder to their iCloud Drive must be disabled.

Apple's iCloud service does not provide an organization with enough control over the storage and access of data and, therefore, automated file synchronization must be controlled by an organization-approved service."
  desc 'check', %q(Verify the macOS system is configured to disable iCloud Desktop and Document folder synchronization with the following command:

/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess')\
.objectForKey('allowCloudDesktopAndDocuments').js
EOS

If the result is not "false", this is a finding.)
  desc 'fix', 'Configure the macOS system to disable iCloud Desktop and Document folder synchronization by installing the "com.apple.applicationaccess" configuration profile.'
  impact 0.5
  tag check_id: 'C-81285r1148840_chk'
  tag severity: 'medium'
  tag gid: 'V-277130'
  tag rid: 'SV-277130r1148842_rule'
  tag stig_id: 'APPL-26-002150'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-81190r1148841_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end

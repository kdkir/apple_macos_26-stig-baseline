control 'SV-277112' do
  title 'The macOS system must disable iCloud Bookmarks.'
  desc "The macOS built-in Safari.app bookmark synchronization via the iCloud service must be disabled.

Apple's iCloud service does not provide an organization with enough control over the storage and access of data and, therefore, automated bookmark synchronization must be controlled by an organization-approved service."
  desc 'check', %q(Verify the macOS system is configured to disable iCloud Bookmarks with the following command:

/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess')\
.objectForKey('allowCloudBookmarks').js
EOS

If the result is not "false", this is a finding.)
  desc 'fix', 'Configure the macOS system to disable iCloud Bookmarks by installing the "com.apple.applicationaccess" configuration profile.'
  impact 0.5
  tag check_id: 'C-81267r1148786_chk'
  tag severity: 'medium'
  tag gid: 'V-277112'
  tag rid: 'SV-277112r1148788_rule'
  tag stig_id: 'APPL-26-002042'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-81172r1148787_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end

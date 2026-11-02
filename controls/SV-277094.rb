control 'SV-277094' do
  title 'The macOS system must disable the iCloud Calendar services.'
  desc "The macOS built-in Calendar.app connection to Apple's iCloud service must be disabled.

Apple's iCloud service does not provide an organization with enough control over the storage and access of data and, therefore, automated calendar synchronization must be controlled by an organization-approved service."
  desc 'check', %q(Verify the macOS system is configured to disable iCloud Calendar services with the following command:

/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess')\
.objectForKey('allowCloudCalendar').js
EOS

If the result is not "false", this is a finding.)
  desc 'fix', 'Configure the macOS system to disable iCloud Calendar services by installing the "com.apple.applicationaccess" configuration profile.'
  impact 0.5
  tag check_id: 'C-81249r1148732_chk'
  tag severity: 'medium'
  tag gid: 'V-277094'
  tag rid: 'SV-277094r1148734_rule'
  tag stig_id: 'APPL-26-002012'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-81154r1148733_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end

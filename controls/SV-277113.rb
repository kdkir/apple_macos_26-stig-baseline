control 'SV-277113' do
  title 'The macOS system must disable iCloud Photo Library.'
  desc "The macOS built-in Photos.app connection to Apple's iCloud service must be disabled.

Apple's iCloud service does not provide an organization with enough control over the storage and access of data and therefore, automated photo synchronization must be controlled by an organization-approved service."
  desc 'check', %q(Verify the macOS system is configured to disable the iCloud Photo Library with the following command:

/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess')\
.objectForKey('allowCloudPhotoLibrary').js
EOS

If the result is not "false", this is a finding.)
  desc 'fix', 'Configure the macOS system to disable the iCloud Photo Library by installing the "com.apple.applicationaccess" configuration profile.'
  impact 0.5
  tag check_id: 'C-81268r1148789_chk'
  tag severity: 'medium'
  tag gid: 'V-277113'
  tag rid: 'SV-277113r1149438_rule'
  tag stig_id: 'APPL-26-002043'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-81173r1148790_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end

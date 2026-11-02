control 'SV-277136' do
  title 'The macOS system must enforce On Device Dictation.'
  desc 'Dictation must be restricted to On Device Only to prevent potential data exfiltration.

The information system must be configured to provide only essential capabilities.'
  desc 'check', %q(For Intel-based systems, this is not applicable.

Verify the macOS system is configured to enforce On Device Only Dictation with the following command:

/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess')\
.objectForKey('forceOnDeviceOnlyDictation').js
EOS

If the result is not "true", this is a finding.)
  desc 'fix', 'Configure the macOS system to enforce On Device Only Dictation by installing the "com.apple.applicationaccess" configuration profile.'
  impact 0.5
  tag check_id: 'C-81291r1148858_chk'
  tag severity: 'medium'
  tag gid: 'V-277136'
  tag rid: 'SV-277136r1148860_rule'
  tag stig_id: 'APPL-26-002220'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-81196r1148859_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']

  if command('/usr/bin/uname -m').stdout.strip != 'arm64'
    impact 0.0
    describe 'On Device Only Dictation' do
      skip 'This requirement is not applicable to Intel-based systems.'
    end
  else
    describe macos_managed_preference('com.apple.applicationaccess', 'forceOnDeviceOnlyDictation') do
      its('value') { should eq true }
    end
  end
end
